#![allow(dead_code)]

#[derive(Debug)]
struct DNSPacketBuffer {
    data: [u8; 512],
    pos: usize,
}

fn main() {
    unimplemented!();
struct DNSHeader {
    id: u16,                    // 16 bits
    query_response: bool,       // 1 bit
    opcode: u8,                 // 4 bits
    authoritative_answer: bool, // 1 bit
    truncated_message: bool,    // 1 bit
    recursion_desired: bool,    // 1 bit
    recursion_available: bool,  // 1 bit
    reserved: u8,               // 3 bits
    response_code: u8,          // 4 bits
    question_count: u16,        // 16 bits
    answer_count: u16,          // 16 bits
    authority_count: u16,       // 16 bits
    additional_count: u16,      // 16 bits
}

