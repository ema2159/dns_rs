use super::{
    DNSDomain, DNSPacketBuffer, DNSPacketErr, DNSRecordPreamble, DNSRecordType, HEADER_SIZE,
};
use std::net::Ipv6Addr;

#[derive(Debug, PartialEq)]
pub struct AAAA {
    pub domain: DNSDomain,
    pub addr: Ipv6Addr,
    pub ttl: u32,
}

impl DNSRecordType for AAAA {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        preamble: DNSRecordPreamble,
    ) -> Result<Self, DNSPacketErr> {
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSPacketErr::BadPointerPosition);
        }

        Ok(AAAA {
            domain: preamble.domain,
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
            ttl: preamble.ttl,
        })
    }

    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        const RECORD_TYPE: u16 = 28;
        const CLASS: u16 = 1;
        const LEN: u16 = 16;
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
    fn test_read_aaaa() {
        let dns_packet_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0xFF, 0x00, 0x10, 0xFF, 0x00, 0x08, 0x0F, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x01, 0xFA, 0x23, 0x55, 0xD4, 0x88,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        dns_packet_buffer.seek(HEADER_SIZE);

        let preamble = DNSRecordPreamble::parse_from_buffer(&mut dns_packet_buffer).unwrap();
        let parsed_record = AAAA::parse_from_buffer(&mut dns_packet_buffer, preamble).unwrap();

        let expected_record = AAAA {
            domain: DNSDomain("google.com".to_string()),
            addr: Ipv6Addr::new(
                0xFF00, 0x080F, 0xAABB, 0xCCDD, 0xEEFF, 0x01FA, 0x2355, 0xD488,
            ),
            ttl: 255,
        };

        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_aaaa() {
        let aaaa_record = AAAA {
            domain: DNSDomain("youtube.com".to_string()),
            addr: Ipv6Addr::new(
                0x080F, 0xFF00, 0xCCDD, 0xAABB, 0x01FA, 0xEEFF, 0xD488, 0x2355,
            ),
            ttl: 171,
        };

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
