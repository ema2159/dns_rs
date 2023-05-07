use super::{
    DNSDomain, DNSPacketBuffer, DNSPacketErr, DNSQueryType, DNSRecordDataRead, DNSRecordDataWrite,
    DNSRecordPreamble,
};

#[derive(Debug, PartialEq)]
pub struct SOA {
    pub mname: DNSDomain,
    pub rname: DNSDomain,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minttl: u32,
}

impl DNSRecordDataRead for SOA {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        _preamble: &DNSRecordPreamble,
    ) -> Result<Self, DNSPacketErr> {
        Ok(SOA {
            mname: DNSDomain::parse_domain(buffer, 0)?,
            rname: DNSDomain::parse_domain(buffer, 0)?,
            serial: buffer.read_u32()?,
            refresh: buffer.read_u32()?,
            retry: buffer.read_u32()?,
            expire: buffer.read_u32()?,
            minttl: buffer.read_u32()?,
        })
    }
}

impl DNSRecordDataWrite for SOA {
    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        let len_field = buffer.get_pos() - 2;
        let starting_pos = buffer.get_pos();

        self.mname.write_to_buffer(buffer)?;
        self.rname.write_to_buffer(buffer)?;
        buffer.write_u32(self.serial)?;
        buffer.write_u32(self.refresh)?;
        buffer.write_u32(self.retry)?;
        buffer.write_u32(self.expire)?;
        buffer.write_u32(self.minttl)?;

        let len = buffer.get_pos() - starting_pos;
        buffer.set_u16(len_field, len as u16)?;

        Ok(())
    }

    fn query_type(&self) -> DNSQueryType {
        DNSQueryType::SOA
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DNSDomain, DNSRecord, DNSRecordData, HEADER_SIZE};
    use super::*;

    #[test]
    fn test_read_soa() {
        let dns_packet_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x73,
            0x70, 0x6C, 0x69, 0x74, 0x6B, 0x62, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x06, 0x00,
            0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x41, 0x03, 0x6E, 0x73, 0x31, 0x03, 0x62, 0x64,
            0x6D, 0x0F, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x6F, 0x6E, 0x6C,
            0x69, 0x6E, 0x65, 0xc0, 0x14, 0x13, 0x61, 0x7A, 0x75, 0x72, 0x65, 0x64, 0x6E, 0x73,
            0x2D, 0x68, 0x6F, 0x73, 0x74, 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x09, 0x6D, 0x69,
            0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0xc0, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x0E, 0x10, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x24, 0xEA, 0x00, 0x00, 0x00, 0x01,
            0x2C,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        dns_packet_buffer.seek(HEADER_SIZE);

        let parsed_record = DNSRecord::parse_from_buffer(&mut dns_packet_buffer).unwrap();

        let expected_record = DNSRecord::new(
            DNSDomain("splitkb.com".to_string()),
            1,
            3600,
            DNSRecordData::SOA(SOA {
                mname: DNSDomain("ns1.bdm.microsoftonline.com".to_string()),
                rname: DNSDomain("azuredns-hostmaster@microsoft.com".to_string()),
                serial: 1,
                refresh: 3600,
                retry: 300,
                expire: 2419200,
                minttl: 300,
            }),
        );

        assert_eq!(parsed_record.preamble.len, 65);
        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_soa() {
        let soa_record = DNSRecord::new(
            DNSDomain("splitkb.com".to_string()),
            1,
            3600,
            DNSRecordData::SOA(SOA {
                mname: DNSDomain("ns1.bdm.microsoftonline.com".to_string()),
                rname: DNSDomain("azuredns-hostmaster@microsoft.com".to_string()),
                serial: 1,
                refresh: 3600,
                retry: 300,
                expire: 2419200,
                minttl: 300,
            }),
        );

        let mut buffer = DNSPacketBuffer::new(&[]);
        buffer.seek(HEADER_SIZE);
        soa_record.write_to_buffer(&mut buffer).unwrap();

        // Expected
        let expected_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x73,
            0x70, 0x6C, 0x69, 0x74, 0x6B, 0x62, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x06, 0x00,
            0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x4E, 0x03, 0x6E, 0x73, 0x31, 0x03, 0x62, 0x64,
            0x6D, 0x0F, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x6F, 0x6E, 0x6C,
            0x69, 0x6E, 0x65, 0xc0, 0x14, 0x13, 0x61, 0x7A, 0x75, 0x72, 0x65, 0x64, 0x6E, 0x73,
            0x2D, 0x68, 0x6F, 0x73, 0x74, 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x09, 0x6D, 0x69,
            0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0xC0, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x0E, 0x10, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x24, 0xEA, 0x00, 0x00, 0x00, 0x01,
            0x2C,
        ];

        let mut expected_buffer = DNSPacketBuffer::new(&expected_data);
        expected_buffer.seek(expected_data.len());

        assert_eq!(buffer.get_data(), expected_buffer.get_data())
    }
}
