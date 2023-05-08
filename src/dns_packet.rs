mod dns_domain;
mod dns_header;
mod dns_packet_buf;
mod dns_packet_err;
mod dns_qtype;
mod dns_question;
mod dns_record;
pub use dns_domain::*;
pub use dns_header::*;
pub use dns_packet_buf::*;
pub use dns_packet_err::*;
pub use dns_qtype::*;
pub use dns_question::*;
pub use dns_record::*;

pub const PACKET_SIZE: usize = 512;
pub const HEADER_SIZE: usize = 12;

#[derive(Debug, PartialEq)]
pub struct DNSPacket {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additional_records: Vec<Record>,
}

impl DNSPacket {
    // NOTE: Constructor
    pub fn new(
        header: Header,
        questions: Option<Vec<Question>>,
        answers: Option<Vec<Record>>,
        authorities: Option<Vec<Record>>,
        additional_records: Option<Vec<Record>>,
    ) -> Self {
        let questions = if let Some(questions) = questions {
            questions
        } else {
            Vec::new()
        };
        let answers = if let Some(answers) = answers {
            answers
        } else {
            Vec::new()
        };
        let authorities = if let Some(authorities) = authorities {
            authorities
        } else {
            Vec::new()
        };
        let additional_records = if let Some(additional_records) = additional_records {
            additional_records
        } else {
            Vec::new()
        };
        DNSPacket {
            header,
            questions,
            answers,
            authorities,
            additional_records,
        }
    }

    // NOTE: Buffer parsing functions

    /// Parse and return DNS header from buffer. Move pointer's position to the byte after the
    /// header.
    fn parse_header(buffer: &mut DNSPacketBuffer) -> Result<Header, DNSError> {
        Header::parse_from_buffer(buffer)
    }

    /// Parse DNS questions starting from the current buffer pointer's position. Move pointer's
    /// position to the byte after the last question.
    fn parse_questions(
        buffer: &mut DNSPacketBuffer,
        num_questions: u16,
    ) -> Result<Vec<Question>, DNSError> {
        let mut questions = Vec::<Question>::new();
        for _ in 0..num_questions {
            questions.push(Question::parse_from_buffer(buffer)?);
        }
        Ok(questions)
    }

    /// Parse DNS record starting from the current buffer pointer's position. Move pointer's
    /// position to the byte after the last answer.
    fn parse_records(
        buffer: &mut DNSPacketBuffer,
        num_records: u16,
    ) -> Result<Vec<Record>, DNSError> {
        let mut records = Vec::<Record>::new();
        for _ in 0..num_records {
            records.push(Record::parse_from_buffer(buffer)?);
        }
        Ok(records)
    }

    /// Parse DNS packet.
    pub fn parse_dns_packet(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSError> {
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

    // NOTE: Buffer writing functions

    /// Write DNS questions to packet buffer.
    fn write_questions(
        questions: &[Question],
        buffer: &mut DNSPacketBuffer,
    ) -> Result<(), DNSError> {
        for question in questions.iter() {
            question.write_to_buffer(buffer)?;
        }

        Ok(())
    }

    /// Write DNS records in packet struct to buffer.
    fn write_records(records: &[Record], buffer: &mut DNSPacketBuffer) -> Result<(), DNSError> {
        for record in records.iter() {
            record.write_to_buffer(buffer)?;
        }

        Ok(())
    }

    /// Write DNS packet.
    pub fn write_dns_packet(&self) -> Result<DNSPacketBuffer, DNSError> {
        let mut buffer = DNSPacketBuffer::new(&[0; PACKET_SIZE]);

        self.header.write_to_buffer(&mut buffer)?;
        Self::write_questions(&self.questions, &mut buffer)?;
        Self::write_records(&self.answers, &mut buffer)?;
        Self::write_records(&self.authorities, &mut buffer)?;
        Self::write_records(&self.additional_records, &mut buffer)?;

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_read_query_packet() {
        let dns_packet_data = [
            0x86, 0x2a, 0x01, 0x20, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x05, 0x79, 0x61, 0x68, 0x6F, 0x6F, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00,
            0x00,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        let parsed_dns_packet = DNSPacket::parse_dns_packet(&mut dns_packet_buffer).unwrap();

        let expected_header = Header {
            id: 0x862a,
            query_response: false,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: true,
            recursion_available: false,
            reserved: 2,
            response_code: ResponseCode::NoError,
            question_count: 2,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        };

        let expected_questions = vec![
            Question {
                domain: Domain("google.com".to_string()),
                record_type: QueryType::A,
                class: 0x01,
            },
            Question {
                domain: Domain("yahoo.com".to_string()),
                record_type: QueryType::A,
                class: 0x00,
            },
        ];

        let expected_answers = Vec::<Record>::new();
        let expected_authorities = Vec::<Record>::new();
        let expected_additional_records = Vec::<Record>::new();

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
    fn test_read_answer_packet_a_record() {
        let dns_packet_data = [
            0x86, 0x2a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xd8, 0x3a,
            0xd3, 0x8e,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        let parsed_dns_packet = DNSPacket::parse_dns_packet(&mut dns_packet_buffer).unwrap();

        let expected_header = Header {
            id: 0x862a,
            query_response: true,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: true,
            recursion_available: true,
            reserved: 0,
            response_code: ResponseCode::NoError,
            question_count: 1,
            answer_count: 1,
            authority_count: 0,
            additional_count: 0,
        };

        let expected_questions = vec![Question {
            domain: Domain("google.com".to_string()),
            record_type: QueryType::A,
            class: 0x01,
        }];

        let expected_answers = vec![Record::new(
            Domain("google.com".to_string()),
            1,
            293,
            RecordData::A(A {
                addr: Ipv4Addr::new(216, 58, 211, 142),
            }),
        )];

        let expected_authorities = Vec::<Record>::new();
        let expected_additional_records = Vec::<Record>::new();

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
    fn test_read_answer_packet_unknown_record() {
        let dns_packet_data = [
            0x86, 0x2a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0xFF, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xd8, 0x3a,
            0xd3, 0x8e, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04,
            0xd8, 0x3a, 0xd3, 0x8e,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        let parsed_dns_packet = DNSPacket::parse_dns_packet(&mut dns_packet_buffer).unwrap();

        let expected_header = Header {
            id: 0x862a,
            query_response: true,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: true,
            recursion_available: true,
            reserved: 0,
            response_code: ResponseCode::NoError,
            question_count: 1,
            answer_count: 2,
            authority_count: 0,
            additional_count: 0,
        };

        let expected_questions = vec![Question {
            domain: Domain("google.com".to_string()),
            record_type: QueryType::A,
            class: 0x01,
        }];

        let expected_answers = vec![
            Record::new(
                Domain("google.com".to_string()),
                1,
                293,
                RecordData::Unknown(Unknown {}),
            ),
            Record::new(
                Domain("google.com".to_string()),
                1,
                293,
                RecordData::A(A {
                    addr: Ipv4Addr::new(216, 58, 211, 142),
                }),
            ),
        ];

        let expected_authorities = Vec::<Record>::new();
        let expected_additional_records = Vec::<Record>::new();

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
    fn test_write_read_0() {
        let original_header = Header {
            id: 0x862a,
            query_response: false,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: true,
            recursion_available: false,
            reserved: 2,
            response_code: ResponseCode::NoError,
            question_count: 5,
            answer_count: 2,
            authority_count: 2,
            additional_count: 2,
        };

        let original_questions = vec![
            Question {
                domain: Domain("google.com".to_string()),
                record_type: QueryType::A,
                class: 0x01,
            },
            Question {
                domain: Domain("yahoo.com".to_string()),
                record_type: QueryType::A,
                class: 0x00,
            },
            Question {
                domain: Domain("dev.google.com".to_string()),
                record_type: QueryType::A,
                class: 0x01,
            },
            Question {
                domain: Domain("api.dev.google.com".to_string()),
                record_type: QueryType::A,
                class: 0x00,
            },
            Question {
                domain: Domain("dev.yahoo.com".to_string()),
                record_type: QueryType::A,
                class: 0x01,
            },
        ];

        let original_answers = vec![
            Record::new(
                Domain("api.dev.google.com".to_string()),
                1,
                342,
                RecordData::A(A {
                    addr: Ipv4Addr::new(16, 28, 21, 42),
                }),
            ),
            Record::new(
                Domain("yahoo.com".to_string()),
                1,
                272,
                RecordData::A(A {
                    addr: Ipv4Addr::new(216, 58, 211, 142),
                }),
            ),
        ];

        let original_authorities = vec![
            Record::new(
                Domain("api.dev.yahoo.com".to_string()),
                1,
                278,
                RecordData::A(A {
                    addr: Ipv4Addr::new(116, 253, 244, 2),
                }),
            ),
            Record::new(
                Domain("yahoo.com".to_string()),
                1,
                22,
                RecordData::A(A {
                    addr: Ipv4Addr::new(255, 244, 233, 222),
                }),
            ),
        ];

        let original_additional_records = vec![
            Record::new(
                Domain("google.com".to_string()),
                1,
                93,
                RecordData::A(A {
                    addr: Ipv4Addr::new(216, 58, 211, 142),
                }),
            ),
            Record::new(
                Domain("api.google.com".to_string()),
                1,
                93,
                RecordData::A(A {
                    addr: Ipv4Addr::new(216, 58, 211, 142),
                }),
            ),
        ];

        let original_packet = DNSPacket::new(
            original_header,
            Some(original_questions),
            Some(original_answers),
            Some(original_authorities),
            Some(original_additional_records),
        );

        let mut dns_packet_buffer = original_packet.write_dns_packet().unwrap();

        // Read
        dns_packet_buffer.seek(0);

        let parsed_packet = DNSPacket::parse_dns_packet(&mut dns_packet_buffer).unwrap();

        assert_eq!(original_packet, parsed_packet);
    }
}
