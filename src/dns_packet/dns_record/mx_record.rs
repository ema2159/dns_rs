use super::{DNSError, DNSPacketBuffer, Domain, QueryType, RecordDataRead, RecordDataWrite};

#[derive(Debug, PartialEq)]
pub struct MX {
    pub preference: u16,
    pub exchange: Domain,
}

impl RecordDataRead for MX {
    fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSError> {
        Ok(MX {
            preference: buffer.read_u16()?,
            exchange: Domain::parse_domain(buffer, 0)?,
        })
    }
}

impl RecordDataWrite for MX {
    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSError> {
        let len_field = buffer.get_pos() - 2;
        let starting_pos = buffer.get_pos();

        buffer.write_u16(self.preference)?;
        self.exchange.write_to_buffer(buffer)?;

        let len = buffer.get_pos() - starting_pos;
        buffer.set_u16(len_field, len as u16)?;

        Ok(())
    }

    fn query_type(&self) -> QueryType {
        QueryType::MX
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Domain, Record, RecordData, HEADER_SIZE};
    use super::*;

    #[test]
    fn test_read_mx() {
        let dns_packet_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x62,
            0x61, 0x72, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
            0x00, 0x00, 0x0F, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFD, 0x00, 0x08, 0x0C, 0x52, 0x03,
            0x66, 0x6F, 0x6F, 0xC0, 0x10,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        dns_packet_buffer.seek(HEADER_SIZE);

        let parsed_record = Record::parse_from_buffer(&mut dns_packet_buffer).unwrap();

        let expected_record = Record::new(
            Domain("bar.example.com".to_string()),
            1,
            253,
            RecordData::MX(MX {
                preference: 3154,
                exchange: Domain("foo.example.com".to_string()),
            }),
        );

        assert_eq!(parsed_record.preamble.len, 8);
        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_mx() {
        let mx_record = Record::new(
            Domain("bar.example.com".to_string()),
            1,
            253,
            RecordData::MX(MX {
                preference: 3154,
                exchange: Domain("foo.example.com".to_string()),
            }),
        );

        let mut buffer = DNSPacketBuffer::new(&[]);
        buffer.seek(HEADER_SIZE);
        mx_record.write_to_buffer(&mut buffer).unwrap();

        // Expected
        let expected_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x62,
            0x61, 0x72, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
            0x00, 0x00, 0x0F, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFD, 0x00, 0x08, 0x0C, 0x52, 0x03,
            0x66, 0x6F, 0x6F, 0xC0, 0x10,
        ];

        let mut expected_buffer = DNSPacketBuffer::new(&expected_data);
        expected_buffer.seek(expected_data.len());

        assert_eq!(buffer.get_data(), expected_buffer.get_data())
    }
}
