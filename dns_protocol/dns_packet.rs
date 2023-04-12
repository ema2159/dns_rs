mod dns_domain;
mod dns_header;
mod dns_packet_err;
mod dns_question;
mod dns_record;
use dns_header::*;
use dns_packet_err::*;
use dns_question::*;
use dns_record::*;

pub struct DNSPacketBuffer {
    data: [u8; 512],
    pos: usize,
}

impl DNSPacketBuffer {
    /// Initializes DNS packet buffer with the given data and its position pointer set to 0.
    pub fn new(data: [u8; 512]) -> Self {
        DNSPacketBuffer { data, pos: 0 }
    }

    // NOTE: Reading methods

    /// Set the buffer's position pointer to a given position.
    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn step(&mut self, steps: usize) {
        self.pos += steps;
    }

    /// Read byte at current position. Don't move position pointer.
    fn get_u8(&self) -> Result<u8, DNSPacketErr> {
        if self.pos >= 512 {
            return Err(DNSPacketErr::EndOfBufferErr);
        }
        let res = self.data[self.pos];

        Ok(res)
    }

    /// Read byte at current position and advance position pointer.
    fn read_u8(&mut self) -> Result<u8, DNSPacketErr> {
        if self.pos >= 512 {
            return Err(DNSPacketErr::EndOfBufferErr);
        }
        let res = self.data[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Read two bytes at current position and advance position pointer.
    fn read_u16(&mut self) -> Result<u16, DNSPacketErr> {
        let high = (self.read_u8()? as u16) << 8;
        let low = self.read_u8()? as u16;

        Ok(high | low)
    }

    /// Read four bytes at current position and advance position pointer.
    fn read_u32(&mut self) -> Result<u32, DNSPacketErr> {
        let first_byte = (self.read_u8()? as u32) << 24;
        let second_byte = (self.read_u8()? as u32) << 16;
        let third_byte = (self.read_u8()? as u32) << 8;
        let fourth_byte = self.read_u8()? as u32;

        Ok(first_byte | second_byte | third_byte | fourth_byte)
    }

    // NOTE: Writing methods

    /// Write byte at current position and advance position pointer.
    fn write_u8(&mut self, val: u8) -> Result<(), DNSPacketErr> {
        if self.pos >= 512 {
            return Err(DNSPacketErr::EndOfBufferErr);
        }

        self.data[self.pos] = val;
        self.pos += 1;

        Ok(())
    }

    /// Write two bytes at current position and advance position pointer.
    fn write_u16(&mut self, val: u16) -> Result<(), DNSPacketErr> {
        if self.pos >= 512 {
            return Err(DNSPacketErr::EndOfBufferErr);
        }

        let first_byte = (val >> 8) as u8;
        let second_byte = (val & 0x00FF) as u8;

        self.write_u8(first_byte)?;
        self.write_u8(second_byte)?;

        Ok(())
    }

    /// Write four bytes at current position and advance position pointer.
    fn write_32(&mut self, val: u16) -> Result<(), DNSPacketErr> {
        if self.pos >= 512 {
            return Err(DNSPacketErr::EndOfBufferErr);
        }

        let first_byte = ((val >> 24) & 0x000000FF) as u8;
        let second_byte = ((val >> 16) & 0x000000FF) as u8;
        let third_byte = ((val >> 8) & 0x000000FF) as u8;
        let fourth_byte = (val & 0x000000FF) as u8;

        self.write_u8(first_byte)?;
        self.write_u8(second_byte)?;
        self.write_u8(third_byte)?;
        self.write_u8(fourth_byte)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct DNSPacket {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additional_records: Vec<DNSRecord>,
}

impl DNSPacket {
    /// Parse and return DNS header from buffer. Move pointer's position to the byte after the
    /// header.
    fn parse_header(buffer: &mut DNSPacketBuffer) -> Result<DNSHeader, DNSPacketErr> {
        let header = DNSHeader::parse_from_buffer(buffer);
        header
    }

    /// Parse DNS questions starting from the current buffer pointer's position. Move pointer's
    /// position to the byte after the last question.
    fn parse_questions(
        buffer: &mut DNSPacketBuffer,
        num_questions: u16,
    ) -> Result<Vec<DNSQuestion>, DNSPacketErr> {
        let mut questions = Vec::<DNSQuestion>::new();
        for _ in 0..num_questions {
            questions.push(DNSQuestion::parse_from_buffer(buffer)?);
        }
        Ok(questions)
    }

    /// Parse DNS record starting from the current buffer pointer's position. Move pointer's
    /// position to the byte after the last answer.
    fn parse_records(
        buffer: &mut DNSPacketBuffer,
        num_records: u16,
    ) -> Result<Vec<DNSRecord>, DNSPacketErr> {
        let mut records = Vec::<DNSRecord>::new();
        for _ in 0..num_records {
            records.push(DNSRecord::parse_from_buffer(buffer)?);
        }
        Ok(records)
    }

    /// Parse DNS information.
    pub fn parse_dns_packet(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        let header = Self::parse_header(buffer)?;
        let questions = Self::parse_questions(buffer, header.question_count)?;
        let answers = Self::parse_records(buffer, header.answer_count)?;
        let authorities = Self::parse_records(buffer, header.authority_count)?;
        let additional_records = Self::parse_records(buffer, header.additional_count)?;
        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additional_records,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_query_packet() {
        let mut dns_packet_data: [u8; 512] = [0; 512];

        dns_packet_data[0..51].clone_from_slice(&[
            0x86, 0x2a, 0x01, 0x20, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77, 0x05, 0x79, 0x61, 0x68, 0x6F, 0x6F,
            0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x00,
        ]);

        let mut dns_packet_buffer = DNSPacketBuffer::new(dns_packet_data);
        let parsed_dns_packet = DNSPacket::parse_dns_packet(&mut dns_packet_buffer).unwrap();

        let expected_header = DNSHeader {
            id: 0x862a,
            query_response: false,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: true,
            recursion_available: false,
            reserved: 2,
            response_code: DNSResponseCode::NOERROR,
            question_count: 2,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        };

        let expected_questions = vec![
            DNSQuestion {
                label_sequence: "www.google.com".to_string(),
                record_type: 0x01,
                class: 0x01,
            },
            DNSQuestion {
                label_sequence: "www.yahoo.com".to_string(),
                record_type: 0x01,
                class: 0x00,
            },
        ];

        let expected_answers = Vec::<DNSRecord>::new();
        let expected_authorities = Vec::<DNSRecord>::new();
        let expected_additional_records = Vec::<DNSRecord>::new();

        let expected_packet = DNSPacket {
            header: expected_header,
            questions: expected_questions,
            answers: expected_answers,
            authorities: expected_authorities,
            additional_records: expected_additional_records,
        };

        assert_eq!(parsed_dns_packet.header, expected_packet.header);
        assert_eq!(parsed_dns_packet.questions, expected_packet.questions);
        assert_eq!(parsed_dns_packet.answers, expected_packet.answers);
    }

    #[test]
    fn test_answer_packet_a_record() {
        let mut dns_packet_data: [u8; 512] = [0; 512];

        dns_packet_data[0..48].clone_from_slice(&[
            0x86, 0x2a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25,
            0x00, 0x04, 0xd8, 0x3a, 0xd3, 0x8e,
        ]);

        let mut dns_packet_buffer = DNSPacketBuffer::new(dns_packet_data);
        let parsed_dns_packet = DNSPacket::parse_dns_packet(&mut dns_packet_buffer).unwrap();

        let expected_header = DNSHeader {
            id: 0x862a,
            query_response: true,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: true,
            recursion_available: true,
            reserved: 0,
            response_code: DNSResponseCode::NOERROR,
            question_count: 1,
            answer_count: 1,
            authority_count: 0,
            additional_count: 0,
        };

        let expected_questions = vec![DNSQuestion {
            label_sequence: "www.google.com".to_string(),
            record_type: 0x01,
            class: 0x01,
        }];

        let expected_answers = vec![DNSRecord::A {
            domain: "www.google.com".to_string(),
            addr: Ipv4Addr::new(216, 58, 211, 142),
            ttl: 293,
        }];

        let expected_authorities = Vec::<DNSRecord>::new();
        let expected_additional_records = Vec::<DNSRecord>::new();

        let expected_packet = DNSPacket {
            header: expected_header,
            questions: expected_questions,
            answers: expected_answers,
            authorities: expected_authorities,
            additional_records: expected_additional_records,
        };

        assert_eq!(parsed_dns_packet.header, expected_packet.header);
        assert_eq!(parsed_dns_packet.questions, expected_packet.questions);
        assert_eq!(parsed_dns_packet.answers, expected_packet.answers);
    }

    #[test]
    fn test_answer_packet_unknown_record() {
        let mut dns_packet_data: [u8; 512] = [0; 512];

        dns_packet_data[..64].clone_from_slice(&[
            0x86, 0x2a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0xFF, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25,
            0x00, 0x04, 0xd8, 0x3a, 0xd3, 0x8e, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x01, 0x25, 0x00, 0x04, 0xd8, 0x3a, 0xd3, 0x8e,
        ]);

        let mut dns_packet_buffer = DNSPacketBuffer::new(dns_packet_data);
        let parsed_dns_packet = DNSPacket::parse_dns_packet(&mut dns_packet_buffer).unwrap();

        let expected_header = DNSHeader {
            id: 0x862a,
            query_response: true,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: true,
            recursion_available: true,
            reserved: 0,
            response_code: DNSResponseCode::NOERROR,
            question_count: 1,
            answer_count: 2,
            authority_count: 0,
            additional_count: 0,
        };

        let expected_questions = vec![DNSQuestion {
            label_sequence: "www.google.com".to_string(),
            record_type: 0x01,
            class: 0x01,
        }];

        let expected_answers = vec![
            DNSRecord::UNKNOWN {
                domain: "www.google.com".to_string(),
                record_type: 255,
                data_len: 4,
                ttl: 293,
            },
            DNSRecord::A {
                domain: "www.google.com".to_string(),
                addr: Ipv4Addr::new(216, 58, 211, 142),
                ttl: 293,
            },
        ];

        let expected_authorities = Vec::<DNSRecord>::new();
        let expected_additional_records = Vec::<DNSRecord>::new();

        let expected_packet = DNSPacket {
            header: expected_header,
            questions: expected_questions,
            answers: expected_answers,
            authorities: expected_authorities,
            additional_records: expected_additional_records,
        };

        assert_eq!(parsed_dns_packet.header, expected_packet.header);
        assert_eq!(parsed_dns_packet.questions, expected_packet.questions);
        assert_eq!(parsed_dns_packet.answers, expected_packet.answers);
    }
}
