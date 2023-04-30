#[cfg(test)]
use super::PACKET_SIZE;
use super::{
    DNSDomain, DNSPacketBuffer, DNSPacketErr, DNSRecordPreamble, DNSRecordType, HEADER_SIZE,
};

#[derive(Debug, PartialEq)]
pub struct Unknown {
    pub domain: DNSDomain,
    pub record_type: u16,
    pub data_len: u16,
    pub ttl: u32,
}

impl DNSRecordType for Unknown {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        preamble: DNSRecordPreamble,
    ) -> Result<Self, DNSPacketErr> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSPacketErr::BadPointerPosition);
        }

        // Skip reading package
        buffer.step(preamble.len as usize);

        let record_type_num = preamble.record_type.to_num();

        Ok(Unknown {
            domain: preamble.domain,
            record_type: record_type_num,
            data_len: preamble.len,
            ttl: preamble.ttl,
        })
    }

    fn write_to_buffer(&self, _buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        Err(DNSPacketErr::UnknownRecord)
    }
}

#[cfg(test)]
mod tests {
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

        let preamble = DNSRecordPreamble::parse_from_buffer(&mut dns_packet_buffer).unwrap();
        let parsed_record = Unknown::parse_from_buffer(&mut dns_packet_buffer, preamble).unwrap();

        let expected_record = Unknown {
            domain: DNSDomain("google.com".to_string()),
            record_type: 255,
            data_len: 4,
            ttl: 293,
        };

        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_unknown() {
        let unknown_record = Unknown {
            domain: DNSDomain("youtube.com".to_string()),
            record_type: 171,
            data_len: 7,
            ttl: 2748,
        };

        let mut buffer = DNSPacketBuffer::new(&[0; PACKET_SIZE]);
        buffer.seek(HEADER_SIZE);
        let err = unknown_record.write_to_buffer(&mut buffer);

        let expected_err = Err(DNSPacketErr::UnknownRecord);

        assert_eq!(err, expected_err)
    }
}
