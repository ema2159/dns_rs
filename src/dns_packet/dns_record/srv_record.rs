use super::{
    DNSError, DNSPacketBuffer, Domain, QueryType, RecordDataRead, RecordDataWrite, RecordPreamble,
};

#[derive(Debug, PartialEq)]
pub struct SRV {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: Domain,
}

impl RecordDataRead for SRV {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        _preamble: &RecordPreamble,
    ) -> Result<Self, DNSError> {
        Ok(SRV {
            priority: buffer.read_u16()?,
            weight: buffer.read_u16()?,
            port: buffer.read_u16()?,
            target: Domain::parse_domain(buffer, 0)?,
        })
    }
}

impl RecordDataWrite for SRV {
    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSError> {
        let len_field = buffer.get_pos() - 2;
        let starting_pos = buffer.get_pos();

        buffer.write_u16(self.priority)?;
        buffer.write_u16(self.weight)?;
        buffer.write_u16(self.port)?;
        self.target.write_to_buffer(buffer)?;

        let len = buffer.get_pos() - starting_pos;
        buffer.set_u16(len_field, len as u16)?;

        Ok(())
    }

    fn query_type(&self) -> QueryType {
        QueryType::SRV
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Domain, Record, RecordData, HEADER_SIZE};
    use super::*;

    #[test]
    fn test_read_srv() {
        let dns_packet_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x62,
            0x61, 0x72, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
            0x00, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFD, 0x00, 0x0C, 0x01, 0x01, 0x0D,
            0x03, 0x92, 0x7c, 0x03, 0x66, 0x6F, 0x6F, 0xC0, 0x10,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        dns_packet_buffer.seek(HEADER_SIZE);

        let parsed_record = Record::parse_from_buffer(&mut dns_packet_buffer).unwrap();

        let expected_record = Record::new(
            Domain("bar.example.com".to_string()),
            1,
            253,
            RecordData::SRV(SRV {
                priority: 257,
                weight: 3331,
                port: 37500,
                target: Domain("foo.example.com".to_string()),
            }),
        );

        assert_eq!(parsed_record.preamble.len, 12);
        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_srv() {
        let srv_record = Record::new(
            Domain("bar.example.com".to_string()),
            1,
            253,
            RecordData::SRV(SRV {
                priority: 257,
                weight: 3331,
                port: 37500,
                target: Domain("foo.example.com".to_string()),
            }),
        );

        let mut buffer = DNSPacketBuffer::new(&[]);
        buffer.seek(HEADER_SIZE);
        srv_record.write_to_buffer(&mut buffer).unwrap();

        // Expected
        let expected_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x62,
            0x61, 0x72, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
            0x00, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFD, 0x00, 0x0C, 0x01, 0x01, 0x0D,
            0x03, 0x92, 0x7c, 0x03, 0x66, 0x6F, 0x6F, 0xC0, 0x10,
        ];

        let mut expected_buffer = DNSPacketBuffer::new(&expected_data);
        expected_buffer.seek(expected_data.len());

        assert_eq!(buffer.get_data(), expected_buffer.get_data())
    }
}
