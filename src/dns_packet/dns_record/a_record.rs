use super::{DNSPacketBuffer, DNSPacketErr, DNSQueryType, DNSRecordDataRead, DNSRecordDataWrite};
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq)]
pub struct A {
    pub addr: Ipv4Addr,
}

impl DNSRecordDataRead for A {
    fn parse_from_buffer(buffer: &mut DNSPacketBuffer) -> Result<Self, DNSPacketErr> {
        Ok(A {
            addr: Ipv4Addr::from(buffer.read_u32()?),
        })
    }
}

impl DNSRecordDataWrite for A {
    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        let len_field = buffer.get_pos() - 2;
        const A_RECORD_LEN: u16 = 4;
        buffer.set_u16(len_field, A_RECORD_LEN)?;

        for octet in self.addr.octets() {
            buffer.write_u8(octet)?;
        }
        Ok(())
    }

    fn query_type(&self) -> DNSQueryType {
        DNSQueryType::A
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DNSDomain, DNSRecord, DNSRecordData, HEADER_SIZE};
    use super::*;

    #[test]
    fn test_read_a() {
        let dns_packet_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0xFF, 0x00, 0x04, 0xFF, 0x00, 0x08, 0x0F,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        dns_packet_buffer.seek(HEADER_SIZE);

        let parsed_record = DNSRecord::parse_from_buffer(&mut dns_packet_buffer).unwrap();

        let expected_record = DNSRecord::new(
            DNSDomain("google.com".to_string()),
            1,
            255,
            DNSRecordData::A(A {
                addr: Ipv4Addr::new(255, 0, 8, 15),
            }),
        );

        assert_eq!(parsed_record.preamble.len, 4);
        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_a() {
        let a_record = DNSRecord::new(
            DNSDomain("youtube.com".to_string()),
            1,
            171,
            DNSRecordData::A(A {
                addr: Ipv4Addr::new(255, 20, 28, 35),
            }),
        );

        let mut buffer = DNSPacketBuffer::new(&[]);
        buffer.seek(HEADER_SIZE);
        a_record.write_to_buffer(&mut buffer).unwrap();

        // Expected
        let expected_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x79,
            0x6f, 0x75, 0x74, 0x75, 0x62, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x00, 0xAB, 0x00, 0x04, 0xFF, 0x14, 0x1C, 0x23,
        ];

        let mut expected_buffer = DNSPacketBuffer::new(&expected_data);
        expected_buffer.seek(expected_data.len());

        assert_eq!(buffer.get_data(), expected_buffer.get_data())
    }
}
