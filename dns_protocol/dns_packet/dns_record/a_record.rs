#[cfg(test)]
use super::PACKET_SIZE;
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
        if buffer.get_pos() < HEADER_SIZE {
            return Err(DNSPacketErr::BadPointerPosition);
        }

        Ok(A {
            domain: preamble.domain,
            addr: Ipv4Addr::from(buffer.read_u32()?),
            ttl: preamble.ttl,
        })
    }

    fn write_to_buffer(self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
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
        let dns_packet_records = [
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x04, 0xFF, 0x00, 0x08, 0x0F,
        ];
        let mut dns_packet_data: [u8; PACKET_SIZE] = [0; PACKET_SIZE];

        dns_packet_data[HEADER_SIZE..HEADER_SIZE + dns_packet_records.len()]
            .clone_from_slice(&dns_packet_records);

        let mut dns_packet_buffer = DNSPacketBuffer::new(dns_packet_data);
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
}
