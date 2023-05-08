use super::{
    DNSDomain, DNSPacketBuffer, DNSPacketErr, DNSQueryType, DNSRecordDataRead, DNSRecordDataWrite,
};

#[derive(Debug, PartialEq)]
pub struct CNAME {
    pub cname: DNSDomain,
}

impl DNSRecordDataRead for CNAME {
    fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        Ok(CNAME {
            cname: DNSDomain::parse_domain(buffer, 0)?,
        })
    }
}

impl DNSRecordDataWrite for CNAME {
    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        let len_field = buffer.get_pos() - 2;
        let starting_pos = buffer.get_pos();

        self.cname.write_to_buffer(buffer)?;

        let len = buffer.get_pos() - starting_pos;
        buffer.set_u16(len_field, len as u16)?;

        Ok(())
    }

    fn query_type(&self) -> DNSQueryType {
        DNSQueryType::CNAME
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DNSDomain, DNSRecord, DNSRecordData, HEADER_SIZE};
    use super::*;

    #[test]
    fn test_read_cname() {
        let dns_packet_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x62,
            0x61, 0x72, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
            0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x06, 0x03, 0x66, 0x6F,
            0x6F, 0xC0, 0x10,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        dns_packet_buffer.seek(HEADER_SIZE);

        let parsed_record = DNSRecord::parse_from_buffer(&mut dns_packet_buffer).unwrap();

        let expected_record = DNSRecord::new(
            DNSDomain("bar.example.com".to_string()),
            1,
            254,
            DNSRecordData::CNAME(CNAME {
                cname: DNSDomain("foo.example.com".to_string()),
            }),
        );

        assert_eq!(parsed_record.preamble.len, 6);
        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_cname() {
        let a_record = DNSRecord::new(
            DNSDomain("bar.example.com".to_string()),
            1,
            254,
            DNSRecordData::CNAME(CNAME {
                cname: DNSDomain("foo.example.com".to_string()),
            }),
        );

        let mut buffer = DNSPacketBuffer::new(&[]);
        buffer.seek(HEADER_SIZE);
        a_record.write_to_buffer(&mut buffer).unwrap();

        // Expected
        let expected_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x62,
            0x61, 0x72, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
            0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x06, 0x03, 0x66, 0x6F,
            0x6F, 0xC0, 0x10,
        ];

        let mut expected_buffer = DNSPacketBuffer::new(&expected_data);
        expected_buffer.seek(expected_data.len());

        assert_eq!(buffer.get_data(), expected_buffer.get_data())
    }
}
