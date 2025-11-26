use std::collections::HashMap;
use std::time::Instant;

use goblin::Object;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

#[derive(Debug, Clone)]
struct ImportInformation {
    name: String,
    ordinal: u16,
    offset: usize,
    rva: usize,
    size: usize,
}

struct DisassembledLines {
    address: u64,
    text: String,
}

fn main() {
    let start = Instant::now();

    // my test bin is just a hello world, i wont be shipping it to github so you will need to compile one yourself and update the path.
    let bin = std::fs::read("./test_files/testpe.bin").unwrap();
    let mut disassembly: Vec<DisassembledLines> = Vec::new();

    let mut imports: HashMap<String, Vec<ImportInformation>> = HashMap::new();

    match Object::parse(&bin).unwrap() {
        Object::PE(pe) => {
            for import in pe.imports {
                imports
                    .entry(import.dll.to_string())
                    .or_insert(vec![])
                    .push(ImportInformation {
                        name: import.name.to_string(),
                        ordinal: import.ordinal,
                        offset: import.offset,
                        rva: import.offset,
                        size: import.size,
                    });
            }

            let dot_text = pe
                .sections
                .iter()
                .find(|s| String::from_utf8_lossy(&s.name).trim_matches('\0') == ".text")
                .expect(".text section not found");

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
                    address: instruction.ip(),
                    text: output.clone(),
                });

                println!("{:016X}  {}", instruction.ip(), output);
            }
        }
        //Object::Elf(elf) => println!("ELF: {:?}", elf.header),
        //Object::Mach(mach) => println!("Mach-O: {:?}", mach),
        _ => {}
    }

    println!("timer: {:?}", start.elapsed());
}