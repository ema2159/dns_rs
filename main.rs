#![allow(dead_code)]

#[derive(Debug)]
enum PacketReadError {
    EndOfBufferErr,
}

#[derive(Debug)]
struct DNSPacketBuffer {
    data: [u8; 512],
    pos: usize,
}

#[derive(Debug, PartialEq)]
struct DNSHeader {
    id: u16,                    // 2 bytes
    query_response: bool,       // 1 bit
    opcode: u8,                 // 4 bits
    authoritative_answer: bool, // 1 bit
    truncated_message: bool,    // 1 bit
    recursion_desired: bool,    // 1 bit
    recursion_available: bool,  // 1 bit
    reserved: u8,               // 3 bits
    response_code: u8,          // 4 bits
    question_count: u16,        // 2 bytes
    answer_count: u16,          // 2 bytes
    authority_count: u16,       // 2 bytes
    additional_count: u16,      // 2 bytes
}



impl DNSHeader {
    fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, PacketReadError> {
        let id = buffer.read_u16()?;

        let mut next_byte = buffer.read_u8()?;
        let query_response = next_byte & 0b1000_0000 != 0;
        let opcode = (next_byte & 0b0111_1000) >> 3;
        let authoritative_answer = next_byte & 0b0000_0100 != 0;
        let truncated_message = next_byte & 0b0000_010 != 0;
        let recursion_desired = next_byte & 0b0000_001 != 0;


        next_byte = buffer.read_u8()?;
        let recursion_available = next_byte & 0b1000_0000 != 0;
        let reserved = (next_byte & 0b0111_0000) >> 4;
        let response_code = next_byte & 0b0000_1111;

        let question_count = buffer.read_u16()?;
        let answer_count = buffer.read_u16()?;
        let authority_count = buffer.read_u16()?;
        let additional_count = buffer.read_u16()?;

        Ok(DNSHeader {
            id,
            query_response,
            opcode,
            authoritative_answer,
            truncated_message,
            recursion_desired,
            recursion_available,
            reserved,
            response_code,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        })
    }
}

impl DNSPacketBuffer {
    pub fn new(data: [u8; 512]) -> Self {
        DNSPacketBuffer { data, pos: 0 }
    }

    fn extract_header(&mut self) -> Result<DNSHeader, PacketReadError> {
       let header = DNSHeader::parse_from_buffer(self);
       header
    }

    fn read_u8(&mut self) -> Result<u8, PacketReadError> {
        if self.pos >= 512 {
            return Err(PacketReadError::EndOfBufferErr);
        }
        let res = self.data[self.pos];
        self.pos += 1;
        return Ok(res)
    }

    fn read_u16(&mut self) -> Result<u16, PacketReadError> {
        let high = (self.read_u8()? as u16) << 8;
        let low = self.read_u8()? as u16;

        return Ok(high | low)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HEADER: [u8; 10] = [0x86, 0x2a, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    const PACKET_TAIL: [u8; 502] = [0; 502];

    #[test]
    fn test_dnsheader() {
        let packet_data: [u8; 512] = [&TEST_HEADER[..], &PACKET_TAIL[..]]
            .concat()
            .try_into()
            .unwrap();
        let dns_buffer = DNSPacketBuffer::new(packet_data);
        let dns_header = dns_buffer.read_header().unwrap();

        let expected_dns_header = DNSHeader {
            id: 0x862a,
            query_response: false,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: true,
            recursion_available: false,
            reserved: 2,
            response_code: 0,
            question_count: 1,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        };

        assert_eq!(dns_header, expected_dns_header);
    }
}
