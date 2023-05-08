use super::{
    DNSError, DNSPacketBuffer, QueryType, RecordDataRead, RecordDataWrite, RecordPreamble,
};
use std::net::Ipv6Addr;

#[derive(Debug, PartialEq)]
pub struct AAAA {
    pub addr: Ipv6Addr,
}

impl RecordDataRead for AAAA {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        _preamble: &RecordPreamble,
    ) -> Result<Self, DNSError> {
        Ok(AAAA {
            addr: Ipv6Addr::new(
                buffer.read_u16()?,
                buffer.read_u16()?,
                buffer.read_u16()?,
                buffer.read_u16()?,
                buffer.read_u16()?,
                buffer.read_u16()?,
                buffer.read_u16()?,
                buffer.read_u16()?,
            ),
        })
    }
}

impl RecordDataWrite for AAAA {
    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSError> {
        let len_field = buffer.get_pos() - 2;
        const AAAA_RECORD_LEN: u16 = 16;
        buffer.set_u16(len_field, AAAA_RECORD_LEN)?;

        for octet in self.addr.octets() {
            buffer.write_u8(octet)?;
        }
        Ok(())
    }

    fn query_type(&self) -> QueryType {
        QueryType::AAAA
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Domain, Record, RecordData, HEADER_SIZE};
    use super::*;

    #[test]
    fn test_read_aaaa() {
        let dns_packet_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1C, 0x00, 0x01,
            0x00, 0x00, 0x00, 0xFF, 0x00, 0x10, 0xFF, 0x00, 0x08, 0x0F, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x01, 0xFA, 0x23, 0x55, 0xD4, 0x88,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        dns_packet_buffer.seek(HEADER_SIZE);

        let parsed_record = Record::parse_from_buffer(&mut dns_packet_buffer).unwrap();

        let expected_record = Record::new(
            Domain("google.com".to_string()),
            1,
            255,
            RecordData::AAAA(AAAA {
                addr: Ipv6Addr::new(
                    0xFF00, 0x080F, 0xAABB, 0xCCDD, 0xEEFF, 0x01FA, 0x2355, 0xD488,
                ),
            }),
        );

        assert_eq!(parsed_record.preamble.len, 16);
        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_aaaa() {
        let aaaa_record = Record::new(
            Domain("youtube.com".to_string()),
            1,
            171,
            RecordData::AAAA(AAAA {
                addr: Ipv6Addr::new(
                    0x080F, 0xFF00, 0xCCDD, 0xAABB, 0x01FA, 0xEEFF, 0xD488, 0x2355,
                ),
            }),
        );

        let mut buffer = DNSPacketBuffer::new(&[]);
        buffer.seek(HEADER_SIZE);
        aaaa_record.write_to_buffer(&mut buffer).unwrap();

        // Expected
        let expected_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x79,
            0x6f, 0x75, 0x74, 0x75, 0x62, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1C, 0x00,
            0x01, 0x00, 0x00, 0x00, 0xAB, 0x00, 0x10, 0x08, 0x0F, 0xFF, 0x00, 0xCC, 0xDD, 0xAA,
            0xBB, 0x01, 0xFA, 0xEE, 0xFF, 0xD4, 0x88, 0x23, 0x55,
        ];

        let mut expected_buffer = DNSPacketBuffer::new(&expected_data);
        expected_buffer.seek(expected_data.len());

        assert_eq!(buffer.get_data(), expected_buffer.get_data())
    }
}
