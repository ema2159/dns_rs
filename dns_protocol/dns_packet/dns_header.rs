use super::DNSPacketBuffer;
use super::DNSPacketErr;
#[cfg(test)]
use super::{HEADER_SIZE, PACKET_SIZE};

#[derive(Debug, PartialEq)]
pub enum DNSResponseCode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NoTimp,
    Refused,
    YXDomain,
    XRRset,
    NoAuth,
    NotZone,
}

impl DNSResponseCode {
    fn from_num(code_num: u8) -> Result<DNSResponseCode, DNSPacketErr> {
        match code_num {
            0 => Ok(Self::NoError),
            1 => Ok(Self::FormErr),
            2 => Ok(Self::ServFail),
            3 => Ok(Self::NXDomain),
            4 => Ok(Self::NoTimp),
            5 => Ok(Self::Refused),
            6 => Ok(Self::YXDomain),
            7 => Ok(Self::XRRset),
            8 => Ok(Self::NoAuth),
            9 => Ok(Self::NotZone),
            _ => Err(DNSPacketErr::UnknownResponseCode(code_num)),
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
        if buffer.get_pos() != 0 {
            return Err(DNSPacketErr::BadPointerPosition);
        }

        let id = buffer.read_u16()?;

        let mut next_byte = buffer.read_u8()?;
        let query_response = next_byte & 0b1000_0000 != 0;
        let opcode = (next_byte & 0b0111_1000) >> 3;
        let authoritative_answer = next_byte & 0b0000_0100 != 0;
        let truncated_message = next_byte & 0b0000_0010 != 0;
        let recursion_desired = next_byte & 0b0000_0001 != 0;

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

    pub fn write_to_buffer(self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        // NOTE: First and second bytes
        buffer.write_u16(self.id)?;

        // NOTE: Third byte
        let third_byte = (self.query_response as u8) << 7
            | self.opcode << 3
            | (self.authoritative_answer as u8) << 2
            | (self.truncated_message as u8) << 1
            | (self.recursion_desired as u8);

        buffer.write_u8(third_byte)?;

        // NOTE: Fourth byte
        let fourth_byte =
            (self.recursion_available as u8) << 7 | self.reserved << 4 | (self.response_code as u8);

        buffer.write_u8(fourth_byte)?;

        // NOTE: Fifth to twelveth bytes
        buffer.write_u16(self.question_count)?;
        buffer.write_u16(self.answer_count)?;
        buffer.write_u16(self.authority_count)?;
        buffer.write_u16(self.additional_count)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_header() {
        let dns_packet_init = [
            0x55, 0x44, 0x7E, 0xF9, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x91,
        ];
        let mut dns_packet_data: [u8; PACKET_SIZE] = [0; PACKET_SIZE];

        dns_packet_data[..dns_packet_init.len()].clone_from_slice(&dns_packet_init);

        let mut dns_packet_buffer = DNSPacketBuffer::new(dns_packet_data);
        let parsed_dns_header = DNSHeader::parse_from_buffer(&mut dns_packet_buffer).unwrap();

        let expected_header = DNSHeader {
            id: 0x5544,
            query_response: false,
            opcode: 15,
            authoritative_answer: true,
            truncated_message: true,
            recursion_desired: false,
            recursion_available: true,
            reserved: 7,
            response_code: DNSResponseCode::NotZone,
            question_count: 0xABCD,
            answer_count: 0xEF12,
            authority_count: 0x3456,
            additional_count: 0x7891,
        };

        assert_eq!(parsed_dns_header, expected_header);
    }

    #[test]
    fn test_wrong_rcode() {
        let dns_packet_init = [
            0x55, 0x44, 0x7E, 0xFF, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x91,
        ];
        let mut dns_packet_data: [u8; PACKET_SIZE] = [0; PACKET_SIZE];

        dns_packet_data[..dns_packet_init.len()].clone_from_slice(&dns_packet_init);

        let mut dns_packet_buffer = DNSPacketBuffer::new(dns_packet_data);
        let parsed_dns_header = DNSHeader::parse_from_buffer(&mut dns_packet_buffer);

        let expected = Err(DNSPacketErr::UnknownResponseCode(0xF));

        assert_eq!(parsed_dns_header, expected);
    }

    #[test]
    fn test_write_to_buffer() {
        let header = DNSHeader {
            id: 0x5544,
            query_response: false,
            opcode: 15,
            authoritative_answer: false,
            truncated_message: true,
            recursion_desired: false,
            recursion_available: true,
            reserved: 7,
            response_code: DNSResponseCode::NotZone,
            question_count: 0xABCD,
            answer_count: 0xEF12,
            authority_count: 0x3456,
            additional_count: 0x7891,
        };

        let mut buffer = DNSPacketBuffer::new([0; PACKET_SIZE]);

        header.write_to_buffer(&mut buffer).unwrap();

        // Expected
        let dns_packet_init = [
            0x55, 0x44, 0x7A, 0xF9, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x91,
        ];
        let mut dns_packet_data: [u8; PACKET_SIZE] = [0; PACKET_SIZE];

        dns_packet_data[..dns_packet_init.len()].clone_from_slice(&dns_packet_init);

        let mut expected_buffer = DNSPacketBuffer::new(dns_packet_data);
        expected_buffer.seek(HEADER_SIZE);

        assert_eq!(buffer, expected_buffer)
    }
}
