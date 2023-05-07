#[cfg(test)]
use super::PACKET_SIZE;
use super::{
    DNSPacketBuffer, DNSPacketErr, DNSQueryType, DNSRecordDataRead, DNSRecordDataWrite,
    DNSRecordPreamble,
};

#[derive(Debug, PartialEq)]
pub struct Unknown {
    pub code: u16,
}

impl DNSRecordDataRead for Unknown {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        preamble: &DNSRecordPreamble,
    ) -> Result<Self, DNSPacketErr> {
        // Skip reading package
        buffer.step(preamble.len as usize);

        Ok(Unknown {
            code: preamble.record_type.to_num(),
        })
    }
}
impl DNSRecordDataWrite for Unknown {
    fn write_to_buffer(&self, _buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        Err(DNSPacketErr::UnknownRecord)
    }

    fn query_type(&self) -> DNSQueryType {
        DNSQueryType::Unknown(self.code)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DNSDomain, DNSRecord, DNSRecordData, HEADER_SIZE};
    use super::*;

    #[test]
    fn test_read_unknown() {
        let dns_packet_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0xFF, 0x00, 0x01,
            0x00, 0x00, 0x01, 0x25, 0x00, 0x05, 0xFF, 0xFF, 0xFF, 0xFF,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        dns_packet_buffer.seek(HEADER_SIZE);

        let parsed_record = DNSRecord::parse_from_buffer(&mut dns_packet_buffer).unwrap();

        let expected_record = DNSRecord::new(
            DNSDomain("google.com".to_string()),
            1,
            293,
            DNSRecordData::Unknown(Unknown { code: 255 }),
        );

        assert_eq!(parsed_record.preamble.len, 5);
        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_unknown() {
        let unknown_record = Unknown { code: 0 };

        let mut buffer = DNSPacketBuffer::new(&[0; PACKET_SIZE]);
        buffer.seek(HEADER_SIZE);
        let err = unknown_record.write_to_buffer(&mut buffer);

        let expected_err = Err(DNSPacketErr::UnknownRecord);

        assert_eq!(err, expected_err)
    }
}
