#[cfg(test)]
use super::PACKET_SIZE;
use super::{
    DNSPacketBuffer, DNSPacketErr, DNSRecordDataRead, DNSRecordDataWrite, DNSRecordPreamble,
};

#[derive(Debug, PartialEq)]
pub struct Unknown {}

impl DNSRecordDataRead for Unknown {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        preamble: &DNSRecordPreamble,
    ) -> Result<Self, DNSPacketErr> {
        // Skip reading package
        buffer.step(preamble.len as usize);

        Ok(Unknown {})
    }
}
impl DNSRecordDataWrite for Unknown {
    fn write_to_buffer(&self, _buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        Err(DNSPacketErr::UnknownRecord)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DNSDomain, DNSQueryType, DNSRecord, DNSRecordData, HEADER_SIZE};
    use super::*;

    #[test]
    fn test_read_unknown() {
        let dns_packet_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0xFF, 0x00, 0x01,
            0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        dns_packet_buffer.seek(HEADER_SIZE);

        let parsed_record = DNSRecord::parse_from_buffer(&mut dns_packet_buffer).unwrap();

        let expected_record = DNSRecord {
            preamble: DNSRecordPreamble {
                domain: DNSDomain("google.com".to_string()),
                record_type: DNSQueryType::Unknown(255),
                class: 1,
                ttl: 293,
                len: 4,
            },
            data: DNSRecordData::Unknown(Unknown {}),
        };

        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_unknown() {
        let unknown_record = Unknown {};

        let mut buffer = DNSPacketBuffer::new(&[0; PACKET_SIZE]);
        buffer.seek(HEADER_SIZE);
        let err = unknown_record.write_to_buffer(&mut buffer);

        let expected_err = Err(DNSPacketErr::UnknownRecord);

        assert_eq!(err, expected_err)
    }
}
