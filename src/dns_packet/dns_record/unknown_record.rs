#[cfg(test)]
use super::PACKET_SIZE;
use super::{
    DNSError, DNSPacketBuffer, QueryType, RecordDataRead, RecordDataWrite, RecordPreamble,
};

#[derive(Debug, PartialEq)]
pub struct Unknown {}

impl RecordDataRead for Unknown {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        preamble: &RecordPreamble,
    ) -> Result<Self, DNSError> {
        // Skip reading package
        buffer.step(preamble.len as usize);
        Ok(Unknown {})
    }
}
impl RecordDataWrite for Unknown {
    fn write_to_buffer(&self, _buffer: &mut DNSPacketBuffer) -> Result<(), DNSError> {
        Err(DNSError::UnknownRecord)
    }

    fn query_type(&self) -> QueryType {
        QueryType::Unknown(0)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Domain, Record, RecordData, HEADER_SIZE};
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

        let parsed_record = Record::parse_from_buffer(&mut dns_packet_buffer).unwrap();

        let expected_record = Record::new(
            Domain("google.com".to_string()),
            1,
            293,
            RecordData::Unknown(Unknown {}),
        );

        assert_eq!(parsed_record.preamble.len, 5);
        assert_eq!(parsed_record.preamble.record_type, QueryType::Unknown(255));
        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_unknown() {
        let unknown_record = Unknown {};

        let mut buffer = DNSPacketBuffer::new(&[0; PACKET_SIZE]);
        buffer.seek(HEADER_SIZE);
        let err = unknown_record.write_to_buffer(&mut buffer);

        let expected_err = Err(DNSError::UnknownRecord);

        assert_eq!(err, expected_err)
    }
}
