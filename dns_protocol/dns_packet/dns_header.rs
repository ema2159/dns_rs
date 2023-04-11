use crate::dns_protocol::dns_packet::dns_packet_err::DNSPacketErr;
use crate::dns_protocol::dns_packet::DNSPacketBuffer;

#[derive(Debug, PartialEq)]
pub enum DNSResponseCode {
    NOERROR,
    FORMERR,
    SERVFAIL,
    NXDOMAIN,
    NOTIMP,
    REFUSED,
    YXDOMAIN,
    XRRSET,
    NOTAUTH,
    NOTZONE,
}

impl DNSResponseCode {
    fn from_num(code_num: u8) -> Result<DNSResponseCode, DNSPacketErr> {
        match code_num {
            0 => Ok(Self::NOERROR),
            1 => Ok(Self::FORMERR),
            2 => Ok(Self::SERVFAIL),
            3 => Ok(Self::NXDOMAIN),
            4 => Ok(Self::NOTIMP),
            5 => Ok(Self::REFUSED),
            6 => Ok(Self::YXDOMAIN),
            7 => Ok(Self::XRRSET),
            8 => Ok(Self::NOTAUTH),
            9 => Ok(Self::NOTZONE),
            _ => Err(DNSPacketErr::UnknownResponseCodeErr(code_num)),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct DNSHeader {
    pub id: u16,                        // 2 bytes
    pub query_response: bool,           // 1 bit
    pub opcode: u8,                     // 4 bits
    pub authoritative_answer: bool,     // 1 bit
    pub truncated_message: bool,        // 1 bit
    pub recursion_desired: bool,        // 1 bit
    pub recursion_available: bool,      // 1 bit
    pub reserved: u8,                   // 3 bits
    pub response_code: DNSResponseCode, // 4 bits
    pub question_count: u16,            // 2 bytes
    pub answer_count: u16,              // 2 bytes
    pub authority_count: u16,           // 2 bytes
    pub additional_count: u16,          // 2 bytes
}

impl DNSHeader {
    pub fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        if buffer.pos != 0 {
            return Err(DNSPacketErr::BadPointerPositionErr);
        }

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
        let response_code = DNSResponseCode::from_num(next_byte & 0b0000_1111)?;

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
