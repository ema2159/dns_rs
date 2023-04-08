#![allow(dead_code)]

#[derive(Debug)]
struct PacketReadError;

#[derive(Debug)]
struct DNSPacketBuffer {
    data: [u8; 512],
    pos: usize,
}

#[derive(Debug, PartialEq)]
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

impl DNSHeader {
    fn get_id(raw_header: &[u8]) -> Result<u16, PacketReadError> {
        const ID_HIGH_BYTE: usize = 0;
        const ID_LOW_BYTE: usize = 1;
        let id_high: u16 = (raw_header[ID_HIGH_BYTE] as u16) << 8;
        let id_low: u16 = raw_header[ID_LOW_BYTE] as u16;
        let id = id_high | id_low;
        Ok(id)
    }

    fn get_query_response(raw_header: &[u8]) -> Result<bool, PacketReadError> {
        const QR_BYTE: usize = 2;
        let query_response: bool = raw_header[QR_BYTE] & 0b1000_0000 != 0;
        Ok(query_response)
    }

    fn get_opcode(raw_header: &[u8]) -> Result<u8, PacketReadError> {
        const OPCODE_BYTE: usize = 2;
        let opcode: u8 = (raw_header[OPCODE_BYTE] & 0b0111_1000) >> 3;
        Ok(opcode)
    }

    fn get_authoritative_answer(raw_header: &[u8]) -> Result<bool, PacketReadError> {
        const AA_BYTE: usize = 2;
        let authoritative_answer: bool = raw_header[AA_BYTE] & 0b0000_0100 != 0;
        Ok(authoritative_answer)
    }

    fn get_truncated_message(raw_header: &[u8]) -> Result<bool, PacketReadError> {
        const TC_BYTE: usize = 2;
        let truncated_message: bool = raw_header[TC_BYTE] & 0b0000_0010 != 0;
        Ok(truncated_message)
    }

    fn get_recursion_desired(raw_header: &[u8]) -> Result<bool, PacketReadError> {
        const RD_BYTE: usize = 2;
        let recursion_desired: bool = raw_header[RD_BYTE] & 0b0000_0001 != 0;
        Ok(recursion_desired)
    }

    fn get_recursion_available(raw_header: &[u8]) -> Result<bool, PacketReadError> {
        const RA_BYTE: usize = 3;
        let recursion_available: bool = raw_header[RA_BYTE] & 0b1000_0000 != 0;
        Ok(recursion_available)
    }

    fn get_reserved(raw_header: &[u8]) -> Result<u8, PacketReadError> {
        const Z_BYTE: usize = 3;
        let reserved: u8 = (raw_header[Z_BYTE] & 0b0111_0000) >> 4;
        Ok(reserved)
    }

    fn get_response_code(raw_header: &[u8]) -> Result<u8, PacketReadError> {
        const RCODE_BYTE: usize = 3;
        let reserved: u8 = raw_header[RCODE_BYTE] & 0b0000_1111;
        Ok(reserved)
    }

    fn get_question_count(raw_header: &[u8]) -> Result<u16, PacketReadError> {
        const QDCOUNT_HIGH_BYTE: usize = 4;
        const QDCOUNT_LOW_BYTE: usize = 5;
        let question_high: u16 = (raw_header[QDCOUNT_HIGH_BYTE] as u16) << 8;
        let question_low: u16 = raw_header[QDCOUNT_LOW_BYTE] as u16;
        let question = question_high | question_low;
        Ok(question)
    }

    fn get_answer_count(raw_header: &[u8]) -> Result<u16, PacketReadError> {
        const ANCOUNT_HIGH_BYTE: usize = 6;
        const ANCOUNT_LOW_BYTE: usize = 7;
        let answer_high: u16 = (raw_header[ANCOUNT_HIGH_BYTE] as u16) << 8;
        let answer_low: u16 = raw_header[ANCOUNT_LOW_BYTE] as u16;
        let answer = answer_high | answer_low;
        Ok(answer)
    }

    fn get_authority_count(raw_header: &[u8]) -> Result<u16, PacketReadError> {
        const NSCOUNT_HIGH_BYTE: usize = 8;
        const NSCOUNT_LOW_BYTE: usize = 9;
        let authority_count_high: u16 = (raw_header[NSCOUNT_HIGH_BYTE] as u16) << 8;
        let authority_count_low: u16 = raw_header[NSCOUNT_LOW_BYTE] as u16;
        let authority_count = authority_count_high | authority_count_low;
        Ok(authority_count)
    }

    fn get_additional_count(raw_header: &[u8]) -> Result<u16, PacketReadError> {
        const ARCOUNT_HIGH_BYTE: usize = 10;
        const ARCOUNT_LOW_BYTE: usize = 11;
        let additional_count_high: u16 = (raw_header[ARCOUNT_HIGH_BYTE] as u16) << 8;
        let additional_count_low: u16 = raw_header[ARCOUNT_LOW_BYTE] as u16;
        let additional_count = additional_count_high | additional_count_low;
        Ok(additional_count)
    }

    fn parse_from_buffer(buffer: &DNSPacketBuffer) -> Result<Self, PacketReadError> {
        const HEADER_SIZE: usize = 12;
        let raw_header = &buffer.data[..HEADER_SIZE];
        Ok(DNSHeader {
            id: Self::get_id(raw_header)?,
            query_response: Self::get_query_response(raw_header)?,
            opcode: Self::get_opcode(raw_header)?,
            authoritative_answer: Self::get_authoritative_answer(raw_header)?,
            truncated_message: Self::get_truncated_message(raw_header)?,
            recursion_desired: Self::get_recursion_desired(raw_header)?,
            recursion_available: Self::get_recursion_available(raw_header)?,
            reserved: Self::get_reserved(raw_header)?,
            response_code: Self::get_response_code(raw_header)?,
            question_count: Self::get_question_count(raw_header)?,
            answer_count: Self::get_answer_count(raw_header)?,
            authority_count: Self::get_authority_count(raw_header)?,
            additional_count: Self::get_additional_count(raw_header)?,
        })
    }
}

impl DNSPacketBuffer {
    pub fn new(data: [u8; 512]) -> Self {
        DNSPacketBuffer { data, pos: 0 }
    }

    fn read_header(&self) -> Result<DNSHeader, PacketReadError> {
        DNSHeader::parse_from_buffer(&self)
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
