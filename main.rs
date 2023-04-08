#![allow(dead_code)]

#[derive(Debug)]
struct DNSPacketBuffer {
    data: [u8; 512],
    pos: usize,
}

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

#[derive(Debug)]
struct PacketReadError;

impl DNSPacketBuffer {
    pub fn new(data: [u8;512]) -> Self {
        DNSPacketBuffer {
            data,
            pos: 0,
        }
    }

    fn get_id(&self) -> Result<u16, PacketReadError> {
        const ID_HIGH_POS: usize = 0;
        const ID_LOW_POS: usize = 1;
        let id_high: u16 = (self.data[ID_HIGH_POS] as u16) << 8;
        let id_low: u16 = self.data[ID_LOW_POS] as u16;
        let id = id_high | id_low;
        Ok(id)
    }

    fn get_query_response(&self) -> Result<bool, PacketReadError> {
        Ok(true)
    }

    fn get_opcode(&self) -> Result<u8, PacketReadError> {
        Ok(0)
    }

    fn get_authoritative_answer(&self) -> Result<bool, PacketReadError> {
        Ok(true)
    }

    fn get_truncated_message(&self) -> Result<bool, PacketReadError> {
        Ok(true)
    }

    fn get_recursion_desired(&self) -> Result<bool, PacketReadError> {
        Ok(true)
    }

    fn get_recursion_available(&self) -> Result<bool, PacketReadError> {
        Ok(true)
    }

    fn get_reserved(&self) -> Result<u8, PacketReadError> {
        Ok(0)
    }

    fn get_response_code(&self) -> Result<u8, PacketReadError> {
        Ok(0)
    }

    fn get_question_count(&self) -> Result<u16, PacketReadError> {
        Ok(0)
    }

    fn get_answer_count(&self) -> Result<u16, PacketReadError> {
        Ok(0)
    }

    fn get_additional_count(&self) -> Result<u16, PacketReadError> {
        Ok(0)
    }

    fn get_authority_count(&self) -> Result<u16, PacketReadError> {
        Ok(0)
    }

    fn read_header(&self) -> Result<DNSHeader, PacketReadError> {
        DNSHeader {
            id: self.get_id()?,
            query_response: self.get_query_response()?,
            opcode: self.get_opcode()?,
            authoritative_answer: self.get_authoritative_answer()?,
            truncated_message: self.get_truncated_message()?,
            recursion_desired: self.get_recursion_desired()?,
            recursion_available: self.get_recursion_available()?,
            reserved: self.get_reserved()?,
            response_code: self.get_response_code()?,
            question_count: self.get_question_count()?,
            answer_count: self.get_answer_count()?,
            authority_count: self.get_authority_count()?,
            additional_count: self.get_additional_count()?,
        };
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HEADER: [u8; 10] = [0x86, 0x2a, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]; 
    const PACKET_TAIL: [u8; 502] = [0; 502]; 
 
    #[test]
    fn test_id() {
        let packet_data: [u8; 512] = [&TEST_HEADER[..], &PACKET_TAIL[..]].concat().try_into().unwrap();
        let data_buffer = DNSPacketBuffer::new(packet_data);
        assert_eq!(data_buffer.get_id().unwrap(), 0x862a);
    }
}
