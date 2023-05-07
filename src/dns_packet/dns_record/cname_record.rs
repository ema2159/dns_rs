use super::{
    DNSDomain, DNSPacketBuffer, DNSPacketErr, DNSQueryType, DNSRecordDataRead, DNSRecordDataWrite,
    DNSRecordPreamble,
};

#[derive(Debug, PartialEq)]
pub struct CNAME {
    pub value: DNSDomain,
}

impl DNSRecordDataRead for CNAME {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        _preamble: &DNSRecordPreamble,
    ) -> Result<Self, DNSPacketErr> {
        Ok(CNAME {
            value: DNSDomain::parse_domain(buffer, 0)?,
        })
    }
}

impl DNSRecordDataWrite for CNAME {
    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSPacketErr> {
        let len_field = buffer.get_pos() - 2;
        let starting_pos = buffer.get_pos();

        self.value.write_to_buffer(buffer)?;

        let len = buffer.get_pos() - starting_pos;
        buffer.set_u16(len_field, len as u16)?;

        Ok(())
    }

    fn query_type(&self) -> DNSQueryType {
        DNSQueryType::CNAME
    }
}
