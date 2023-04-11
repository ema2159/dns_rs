#![allow(dead_code)]

use std::net::Ipv4Addr;

#[derive(Debug)]
enum DNSPacketErr {
    EndOfBufferErr,
    BadPointerPositionErr,
    UnknownResponseCodeErr(u8),
    UnknownQueryTypeErr(u16),
    NonUTF8LabelErr,
    MaxJumpsErr,
}

#[derive(Debug)]
struct DNSPacketBuffer {
    data: [u8; 512],
    pos: usize,
}

#[derive(Debug, PartialEq)]
enum DNSResponseCode {
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
struct DNSHeader {
    id: u16,                        // 2 bytes
    query_response: bool,           // 1 bit
    opcode: u8,                     // 4 bits
    authoritative_answer: bool,     // 1 bit
    truncated_message: bool,        // 1 bit
    recursion_desired: bool,        // 1 bit
    recursion_available: bool,      // 1 bit
    reserved: u8,                   // 3 bits
    response_code: DNSResponseCode, // 4 bits
    question_count: u16,            // 2 bytes
    answer_count: u16,              // 2 bytes
    authority_count: u16,           // 2 bytes
    additional_count: u16,          // 2 bytes
}

impl DNSHeader {
    fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
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

#[derive(Debug, PartialEq)]
struct DNSQuestion {
    label_sequence: String, // Variable length
    record_type: u16,       // 2 bytes
    class: u16,             // 2 bytes
}

impl DNSQuestion {
    fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        if buffer.pos < 12 {
            return Err(DNSPacketErr::BadPointerPositionErr);
        }

        let label_sequence = buffer.extract_domain(0)?;
        let record_type = buffer.read_u16()?;
        let class = buffer.read_u16()?;
        Ok(DNSQuestion {
            label_sequence,
            record_type,
            class,
        })
    }
}

#[derive(Debug, PartialEq)]
struct DNSRecordPreamble {
    label_sequence: String,    // Variable length
    record_type: DNSQueryType, // 2 bytes
    class: u16,                // 2 bytes
    ttl: u32,                  // 4 bytes
    len: u16,                  // 2 bytes
}

#[derive(Debug, PartialEq)]
enum DNSRecordType {
    A(Ipv4Addr),
}

#[derive(Debug, PartialEq)]
enum DNSQueryType {
    A,
}

impl DNSQueryType {
    fn from_num(code_num: u16) -> Result<DNSQueryType, DNSPacketErr> {
        match code_num {
            1 => Ok(DNSQueryType::A),
            _ => Err(DNSPacketErr::UnknownQueryTypeErr(code_num)),
        }
    }
}

#[derive(Debug, PartialEq)]
struct DNSRecord {
    preamble: DNSRecordPreamble,
    data: DNSRecordType,
}

impl DNSRecord {
    fn extract_type_a(buffer: &mut DNSPacketBuffer) -> Result<DNSRecordType, DNSPacketErr> {
        Ok(DNSRecordType::A(Ipv4Addr::from(buffer.read_u32()?)))
    }

    fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        if buffer.pos < 12 {
            return Err(DNSPacketErr::BadPointerPositionErr);
        }

        let preamble = DNSRecordPreamble {
            label_sequence: buffer.extract_domain(0)?,
            record_type: DNSQueryType::from_num(buffer.read_u16()?)?,
            class: buffer.read_u16()?,
            ttl: buffer.read_u32()?,
            len: buffer.read_u16()?,
        };
        let data = match preamble.record_type {
            DNSQueryType::A => Ok(DNSRecord::extract_type_a(buffer)?),
        }?;
        Ok(DNSRecord { preamble, data })
    }
}

#[derive(Debug, PartialEq)]
struct DNSPacket {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additional_records: Vec<DNSRecord>,
}

impl DNSPacketBuffer {
    /// Initializes DNS packet buffer with the given data and its position pointer set to 0.
    pub fn new(data: [u8; 512]) -> Self {
        DNSPacketBuffer { data, pos: 0 }
    }

    /// Set the buffer's position pointer to a given position.
    fn seek(&mut self, pos: usize) {
        self.pos = pos;
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

    /// Parse and return DNS header from buffer. Move pointer's position to the byte after the
    /// header.
    fn extract_header(&mut self) -> Result<DNSHeader, DNSPacketErr> {
        let header = DNSHeader::parse_from_buffer(self);
        header
    }

    /// Parse DNS domain name composed by labels starting from the current buffer pointer's position. Move pointer's
    /// position to the byte after the last label.
    fn extract_domain(&mut self, jump: u8) -> Result<String, DNSPacketErr> {
        const MAX_JUMPS: u8 = 5;
        if jump == MAX_JUMPS {
            return Err(DNSPacketErr::MaxJumpsErr);
        }

        let mut labels_buf = Vec::<String>::new();

        // Parse each label until a 0 label_size byte is encountered or until a label jump found
        loop {
            let jump_or_len_byte = self.get_u8()?;

            // If two MSBs are 1, mask with 0xC000 and jump to that position to reuse a previous label,
            // then jump back
            if 0b1100_0000 & jump_or_len_byte == 0b1100_0000 {
                let next_pos = self.pos + 2;
                let jump_pos = self.read_u16()? ^ 0b1100_0000_0000_0000;
                self.seek(jump_pos as usize);
                let reused_labels = self.extract_domain(jump + 1)?;
                labels_buf.push(reused_labels);
                self.seek(next_pos);
                break;
            }

            // If byte didn't indicate jump, then it indicates the label size
            let label_size = self.read_u8()?;

            // 0 size byte, finish parsing labels
            if label_size == 0 {
                break;
            }

            let mut label_buf = Vec::<u8>::new();

            // [b'g', b'o', b'o', b'g', b'l', b'e']
            for _ in 0..label_size {
                label_buf.push(self.read_u8()?);
            }

            // [b'g', b'o', b'o', b'g', b'l', b'e'] -> "google"
            let label = (String::from_utf8(label_buf)
                .or_else(|_| Err(DNSPacketErr::NonUTF8LabelErr))?)
            .to_lowercase();

            // ["www"].push("google")
            labels_buf.push(label);
        }

        // ["www", "google", "com"] -> "www.google.com"
        let label_sequence = labels_buf.join(".");

        Ok(label_sequence)
    }

    /// Parse DNS questions starting from the current buffer pointer's position. Move pointer's
    /// position to the byte after the last question.
    fn extract_questions(&mut self, num_questions: u16) -> Result<Vec<DNSQuestion>, DNSPacketErr> {
        let mut questions = Vec::<DNSQuestion>::new();
        for _ in 0..num_questions {
            questions.push(DNSQuestion::parse_from_buffer(self)?);
        }
        Ok(questions)
    }

    /// Parse DNS record starting from the current buffer pointer's position. Move pointer's
    /// position to the byte after the last answer.
    fn extract_records(&mut self, num_records: u16) -> Result<Vec<DNSRecord>, DNSPacketErr> {
        let mut records = Vec::<DNSRecord>::new();
        for _ in 0..num_records {
            records.push(DNSRecord::parse_from_buffer(self)?);
        }
        Ok(records)
    }

    /// Parse DNS information.
    pub fn parse_dns_packet(&mut self) -> Result<DNSPacket, DNSPacketErr> {
        let header = self.extract_header()?;
        let questions = self.extract_questions(header.question_count)?;
        let answers = self.extract_records(header.answer_count)?;
        let authorities = self.extract_records(header.authority_count)?;
        let additional_records = self.extract_records(header.additional_count)?;
        Ok(DNSPacket {
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

    #[test]
    fn test_dnspacket() {
        let mut dns_packet_buffer: [u8; 512] = [0; 512];
        let dns_packet_data: [u8; 51] = [
            0x86, 0x2a, 0x01, 0x20, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77, 0x05, 0x79, 0x61, 0x68, 0x6F, 0x6F,
            0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x00,
        ];

        dns_packet_buffer[0..51].clone_from_slice(&dns_packet_data);

        let parsed_dns_packet = DNSPacketBuffer::new(dns_packet_buffer)
            .parse_dns_packet()
            .unwrap();

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

        let expected_packet = DNSPacket {
            header: expected_header,
            questions: expected_questions,
        };

        assert_eq!(parsed_dns_packet.header, expected_packet.header);
        assert_eq!(parsed_dns_packet.questions, expected_packet.questions);
    }
}
