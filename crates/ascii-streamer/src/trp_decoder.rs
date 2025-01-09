use std::fs::File;
use std::io::{self, Read};
use std::str;

fn decode_trp(buffer: &[u8]) -> anyhow::Result<()> {
    let mut position = 0;
    while position < buffer.len() {
        if position + 8 > buffer.len() {
            eprintln!("Incomplete header at position {}", position);
            break;
        }

        let timer = u32::try_from(buffer[position..position + 4])?;
        // let event_type = read_u16(&buffer, position + 4);
        let event_type = u16::try_from(buffer[position + 4..position + 6])?;
        let size = u16::try_from(buffer[position + 6..position + 8])?;

        if position + 8 + size as usize > buffer.len() {
            eprintln!("Incomplete payload at position {}", position);
            break;
        }

        let payload = &buffer[position + 8..position + 8 + size as usize];

        match event_type {
            0 => {
                // Terminal output
                if let Ok(text) = str::from_utf8(payload) {
                    println!("[Time: {} ms] Terminal Output: {}", timer, text);
                } else {
                    println!("[Time: {} ms] Terminal Output: [Invalid UTF-8]", timer);
                }
            }
            1 => {
                // User input
                if let Ok(text) = str::from_utf8(payload) {
                    println!("[Time: {} ms] User Input: {}", timer, text);
                } else {
                    println!("[Time: {} ms] User Input: [Invalid UTF-8]", timer);
                }
            }
            2 => {
                // Terminal size change
                if payload.len() == 4 {
                    let width = read_u16(payload, 0);
                    let height = read_u16(payload, 2);
                    println!("[Time: {} ms] Terminal Resize: {}x{}", timer, width, height);
                } else {
                    println!("[Time: {} ms] Terminal Resize: [Invalid Size Data]", timer);
                }
            }
            4 => {
                // Terminal setup
                println!("[Time: {} ms] Terminal Setup: [Payload Size: {} bytes]", timer, size);
            }
            _ => {
                println!("[Time: {} ms] Unknown Event Type: {}", timer, event_type);
            }
        }

        position += 8 + size as usize;
    }

    Ok(())
}


#[test]
pub mod test {
    
}