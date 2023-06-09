use super::DNSError;
use super::DNSPacketBuffer;
use super::Domain;
use super::QueryType;
use super::HEADER_SIZE;

#[derive(Debug, PartialEq)]
pub struct Question {
    pub domain: Domain,         // Variable length
    pub record_type: QueryType, // 2 bytes
    pub class: u16,             // 2 bytes
}

impl Question {
    pub(crate) fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSError> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSError::BadPointerPosition);
        }

        let label_sequence = Domain::parse_domain(buffer, 0)?;
        let record_type = QueryType::from_num(buffer.read_u16()?);
        let class = buffer.read_u16()?;
        Ok(Question {
            domain: label_sequence,
            record_type,
            class,
        })
    }

    pub(crate) fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSError> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSError::BadPointerPosition);
        }

        self.domain.write_to_buffer(buffer)?;
        buffer.write_u16(self.record_type.to_num())?;
        buffer.write_u16(self.class)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_question() {
        let dns_packet_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x05, 0x79, 0x61, 0x68, 0x6F, 0x6F, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00,
            0x00,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        dns_packet_buffer.seek(HEADER_SIZE);

        let parsed_question0 = Question::parse_from_buffer(&mut dns_packet_buffer).unwrap();
        let parsed_question1 = Question::parse_from_buffer(&mut dns_packet_buffer).unwrap();

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

        assert_eq!(parsed_question0, expected_questions[0]);
        assert_eq!(parsed_question1, expected_questions[1]);
    }

    #[test]
    fn test_write_question() {
        let question = Question {
            domain: Domain("google.com".to_string()),
            record_type: QueryType::A,
            class: 0x01,
        };

        let mut buffer = DNSPacketBuffer::new(&[]);
        buffer.seek(HEADER_SIZE);

        question.write_to_buffer(&mut buffer).unwrap();

        // Expected
        let dns_packet_question = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let mut expected_buffer = DNSPacketBuffer::new(&dns_packet_question);
        expected_buffer.seek(dns_packet_question.len());

        assert_eq!(buffer.get_data(), expected_buffer.get_data())
    }
}
