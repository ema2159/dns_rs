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
        self.mname.write_to_buffer(buffer)?;
        self.rname.write_to_buffer(buffer)?;
        buffer.write_u32(self.serial)?;
        buffer.write_u32(self.refresh)?;
        buffer.write_u32(self.retry)?;
        buffer.write_u32(self.expire)?;
        buffer.write_u32(self.minttl)?;
        Ok(())
    }

    fn query_type(&self) -> DNSQueryType {
        DNSQueryType::SOA
    }
}
