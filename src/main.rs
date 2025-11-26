use goblin::Object;
use gpui::{
    div, px, size, AppContext, Application, Context, Div, InteractiveElement, IntoElement,
    ParentElement, Render, ScrollHandle, Size, StatefulInteractiveElement, Styled, Window,
    WindowOptions,
};
use gpui_component::{
    scroll::{Scrollbar, ScrollbarState},
    tab::{Tab, TabBar},
    text::Text,
    v_virtual_list, Root, StyledExt, VirtualListScrollHandle,
};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use std::rc::Rc;

pub struct Sunder {
    imports: Vec<ImportInformation>,
    disassembly: Vec<DisassembledLines>,
    active_tab: usize,
    scroll_state: ScrollbarState,
    scroll_handle: ScrollHandle,
    disasm_scroll_handle: VirtualListScrollHandle,
    disasm_item_sizes: Rc<Vec<Size<gpui::Pixels>>>,
}

#[derive(Debug, Clone)]
struct ImportInformation {
    name: String,
    ordinal: u16,
    offset: usize,
    rva: usize,
    size: usize,
}

struct DisassembledLines {
    formatted: String,
}

impl Sunder {
    fn render_imports(&self) -> impl IntoElement {
        div()
            .relative()
            .size_full()
            .child(
                div()
                    .id("imports")
                    .track_scroll(&self.scroll_handle)
                    .overflow_scroll()
                    .size_full()
                    .child(
                        div()
                            .v_flex()
                            .gap_1()
                            .children(self.imports.iter().map(|imp| {
                                div().child(Text::String(
                                    format!(
                                        "Name: {}, Ordinal: {}, Offset: {}, RVA: {}, Size: {}",
                                        imp.name, imp.ordinal, imp.offset, imp.rva, imp.size
                                    )
                                    .into(),
                                ))
                            })),
                    ),
            )
            .child(Scrollbar::vertical(&self.scroll_state, &self.scroll_handle))
    }

    fn render_disassembly(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let item_sizes = self.disasm_item_sizes.clone();
        let disasm_data: Vec<String> = self
            .disassembly
            .iter()
            .map(|l| l.formatted.clone())
            .collect();

        v_virtual_list(
            cx.entity().clone(),
            "disassembly",
            item_sizes,
            move |_view, visible_range, _scroll_handle, _cx| {
                visible_range
                    .map(|ix| div().w_full().h(px(20.)).child(disasm_data[ix].clone()))
                    .collect()
            },
        )
        .track_scroll(&self.disasm_scroll_handle)
        .size_full()
    }

    fn render_how_did_you_get_here(&self) -> Div {
        div().child("How did you get here!!!!!")
    }
}

impl Render for Sunder {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .v_flex()
            .size_full()
            .child(
                TabBar::new("main_tabs")
                    .child(
                        Tab::new()
                            .label("Imports")
                            .on_click(cx.listener(|this, _, _, _| {
                                this.active_tab = 0;
                            })),
                    )
                    .child(Tab::new().label("Disassembly").on_click(cx.listener(
                        |this, _, _, _| {
                            this.active_tab = 1;
                        },
                    ))),
            )
            .child(div().flex_1().size_full().child(match self.active_tab {
                0 => self.render_imports().into_any_element(),
                1 => self.render_disassembly(cx).into_any_element(),
                _ => self.render_how_did_you_get_here().into_any_element(),
            }))
    }
}

fn parse_pe(path: &str) -> (Vec<ImportInformation>, Vec<DisassembledLines>) {
    let bin = std::fs::read(path).unwrap();
    let mut disassembly: Vec<DisassembledLines> = Vec::new();
    let mut imports: Vec<ImportInformation> = Vec::new();

    match Object::parse(&bin).unwrap() {
        Object::PE(pe) => {
            for import in pe.imports {
                imports.push(ImportInformation {
                    name: import.name.to_string(),
                    ordinal: import.ordinal,
                    offset: import.offset,
                    rva: import.offset,
                    size: import.size,
                });
            }

            if let Some(dot_text) = pe
                .sections
                .iter()
                .find(|s| String::from_utf8_lossy(&s.name).trim_matches('\0') == ".text")
            {
                let f_offset = dot_text.pointer_to_raw_data as usize;
                let dot_text_size = dot_text.size_of_raw_data as usize;
                let text_bytes = &bin[f_offset..f_offset + dot_text_size];
                let ip = pe.image_base + dot_text.virtual_address as u64;

                let mut decoder = Decoder::with_ip(64, text_bytes, ip, DecoderOptions::NONE);
                let mut formatter = IntelFormatter::new();
                let mut output = String::new();
                let mut instruction = Instruction::default();

                while decoder.can_decode() {
                    decoder.decode_out(&mut instruction);

                    if instruction.is_invalid() {
                        continue;
                    }

                    output.clear();
                    formatter.format(&instruction, &mut output);

                    disassembly.push(DisassembledLines {
                        formatted: format!("{:016X}  {}", instruction.ip(), output),
                    });
                }
            }
        }
        Object::Elf(_elf) => todo!(),
        Object::Mach(_mach) => todo!(),
        Object::COFF(_coff) => todo!(),
        Object::TE(_te) => todo!(),
        Object::Archive(_archive) => todo!(),
        _ => {}
    }

    (imports, disassembly)
}

fn main() {
    let app = Application::new();

    app.run(move |cx| {
        gpui_component::init(cx);

        // my test bin is just a hello world, i wont be shipping it to github so you will need to compile one yourself and update the path.
        let (imports, disassembly) = parse_pe("./test_files/testpe.bin");

        // to help with the virtual list cuz it gets a tad laggy when not using a virtual list, im new to gpui so ill get something better probably
        let item_sizes: Rc<Vec<Size<gpui::Pixels>>> = Rc::new(
            (0..disassembly.len())
                .map(|_| size(px(800.), px(20.)))
                .collect(),
        );

        cx.open_window(WindowOptions::default(), |window, cx| {
            let view = cx.new(|_| Sunder {
                imports,
                disassembly,
                active_tab: 0,
                scroll_state: ScrollbarState::default(),
                scroll_handle: ScrollHandle::new(),
                disasm_scroll_handle: VirtualListScrollHandle::new(),
                disasm_item_sizes: item_sizes,
            });
            cx.new(|cx| Root::new(view, window, cx))
        })
        .unwrap();
    });
}