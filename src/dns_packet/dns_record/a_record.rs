use super::{
    DNSDomain, DNSPacketBuffer, DNSPacketErr, DNSRecordPreamble, DNSRecordType, HEADER_SIZE,
};
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq)]
pub struct A {
    pub domain: DNSDomain,
    pub addr: Ipv4Addr,
    pub ttl: u32,
}

impl DNSRecordType for A {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        preamble: DNSRecordPreamble,
    ) -> Result<Self, DNSPacketErr> {
        Ok(A {
            domain: preamble.domain,
            addr: Ipv4Addr::from(buffer.read_u32()?),
            ttl: preamble.ttl,
        })
    }

    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        const RECORD_TYPE: u16 = 1;
        const CLASS: u16 = 1;
        const LEN: u16 = 4;
        self.domain.write_to_buffer(buffer)?;
        buffer.write_u16(RECORD_TYPE)?;
        buffer.write_u16(CLASS)?;
        buffer.write_u32(self.ttl)?;
        buffer.write_u16(LEN)?;

        for octet in self.addr.octets() {
            buffer.write_u8(octet)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
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

        let preamble = DNSRecordPreamble::parse_from_buffer(&mut dns_packet_buffer).unwrap();
        let parsed_record = A::parse_from_buffer(&mut dns_packet_buffer, preamble).unwrap();

        let expected_record = A {
            domain: DNSDomain("google.com".to_string()),
            addr: Ipv4Addr::new(255, 0, 8, 15),
            ttl: 255,
        };

        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_a() {
        let a_record = A {
            domain: DNSDomain("youtube.com".to_string()),
            addr: Ipv4Addr::new(255, 20, 28, 35),
            ttl: 171,
        };

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
