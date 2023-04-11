#![allow(dead_code)]

#[derive(Debug)]
enum DNSPacketErr {
    EndOfBufferErr,
    BadPointerPositionErr,
    UnknownResponseCodeErr(u8),
    NonUTF8LabelErr,
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

        let label_sequence = buffer.extract_label()?;
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
struct DNSPacket {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
}

impl DNSPacketBuffer {
    pub fn new(data: [u8; 512]) -> Self {
        DNSPacketBuffer { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, DNSPacketErr> {
        if self.pos >= 512 {
            return Err(DNSPacketErr::EndOfBufferErr);
        }
        let res = self.data[self.pos];
        self.pos += 1;
        return Ok(res);
    }

    fn read_u16(&mut self) -> Result<u16, DNSPacketErr> {
        let high = (self.read_u8()? as u16) << 8;
        let low = self.read_u8()? as u16;

        return Ok(high | low);
    }

    fn extract_header(&mut self) -> Result<DNSHeader, DNSPacketErr> {
        let header = DNSHeader::parse_from_buffer(self);
        header
    }

    fn extract_label(&mut self) -> Result<String, DNSPacketErr> {
        let mut label_size = self.read_u8()?;
        let mut labels_buf = Vec::<u8>::new();

        // Parse each label until a 0 label_size byte is encountered
        while label_size != 0 {
            for _ in 0..label_size {
                labels_buf.push(self.read_u8()?);
            }
            labels_buf.push(b'.');
            label_size = self.read_u8()?;
        }
        labels_buf.pop(); // Remove last '.' in domain name i.e. avoid www.google.com.

        let label_sequence =
            String::from_utf8(labels_buf).or_else(|_| Err(DNSPacketErr::LabelParsingErr))?;

        Ok(label_sequence)
            .or_else(|_| Err(DNSPacketErr::NonUTF8LabelErr))?)
    }

    fn extract_questions(&mut self, num_questions: u16) -> Result<Vec<DNSQuestion>, DNSPacketErr> {
        let mut questions = Vec::<DNSQuestion>::new();
        for _ in 0..num_questions {
            questions.push(DNSQuestion::parse_from_buffer(self)?);
        }
        Ok(questions)
    }

    pub fn parse_dns_packet(&mut self) -> Result<DNSPacket, DNSPacketErr> {
        let header = self.extract_header()?;
        let num_questions = header.question_count;
        let questions = self.extract_questions(num_questions)?;
        Ok(DNSPacket { header, questions })
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
