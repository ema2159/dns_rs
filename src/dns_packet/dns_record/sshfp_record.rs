use super::{
    DNSError, DNSPacketBuffer, QueryType, RecordDataRead, RecordDataWrite, RecordPreamble,
};

#[derive(Debug, PartialEq)]
pub enum Algorithm {
    Reserved,
    RSA,
    DSA,
    ECDSA,
    ED25519,
    Unassigned(u8),
    ED448,
}

impl Algorithm {
    fn from_num(code_num: u8) -> Self {
        match code_num {
            0 => Self::Reserved,
            1 => Self::RSA,
            2 => Self::DSA,
            3 => Self::ECDSA,
            4 => Self::ED25519,
            6 => Self::ED448,
            _ => Self::Unassigned(code_num),
        }
    }

    fn to_num(&self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::RSA => 1,
            Self::DSA => 2,
            Self::ECDSA => 3,
            Self::ED25519 => 4,
            Self::ED448 => 6,
            Self::Unassigned(num) => *num,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum FingerprintType {
    Reserved,
    SHA1,
    SHA256,
    Unassigned(u8),
}

impl FingerprintType {
    fn from_num(code_num: u8) -> Self {
        match code_num {
            0 => Self::Reserved,
            1 => Self::SHA1,
            2 => Self::SHA256,
            _ => Self::Unassigned(code_num),
        }
    }

    fn to_num(&self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::SHA1 => 1,
            Self::SHA256 => 2,
            Self::Unassigned(num) => *num,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct SSHFP {
    pub algorithm: Algorithm,              // 1 byte
    pub fingerprint_type: FingerprintType, // 1 byte
    pub fingerprint: String,               // Variable length
}

impl RecordDataRead for SSHFP {
    fn parse_from_buffer(
        buffer: &mut DNSPacketBuffer,
        preamble: &RecordPreamble,
    ) -> Result<Self, DNSError> {
        let algorithm = Algorithm::from_num(buffer.read_u8()?);
        let fingerprint_type = FingerprintType::from_num(buffer.read_u8()?);

        let fingerprint_start = buffer.get_pos();
        let fingerprint_end = fingerprint_start + preamble.len as usize - 2; // minus two bytes from the two previous fields
        let fingerprint_slice = &buffer.get_data()[fingerprint_start..fingerprint_end];
        let fingerprint_str =
            String::from_utf8(fingerprint_slice.to_vec()).map_err(|_| DNSError::NonUTF8)?;

        buffer.step(preamble.len as usize);

        Ok(SSHFP {
            algorithm,
            fingerprint_type,
            fingerprint: fingerprint_str,
        })
    }
}

impl RecordDataWrite for SSHFP {
    fn write_to_buffer(&self, buffer: &mut DNSPacketBuffer) -> Result<(), DNSError> {
        let len_field = buffer.get_pos() - 2;
        let starting_pos = buffer.get_pos();

        let algorithm = match self.algorithm {
            Algorithm::Reserved | Algorithm::Unassigned(_) => {
                return Err(DNSError::ReservedOrUnassigned)
            }
            _ => self.algorithm.to_num(),
        };

        let fingerprint_type = match self.fingerprint_type {
            FingerprintType::Reserved | FingerprintType::Unassigned(_) => {
                return Err(DNSError::ReservedOrUnassigned)
            }
            _ => self.fingerprint_type.to_num(),
        };

        buffer.write_u8(algorithm)?;
        buffer.write_u8(fingerprint_type)?;

        for b in self.fingerprint.as_bytes() {
            buffer.write_u8(*b)?;
        }
        let len = buffer.get_pos() - starting_pos;
        buffer.set_u16(len_field, len as u16)?;

        Ok(())
    }

    fn query_type(&self) -> QueryType {
        QueryType::SSHFP
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Domain, Record, RecordData, HEADER_SIZE};
    use super::*;

    #[test]
    fn test_read_sshfp() {
        let dns_packet_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x62,
            0x61, 0x72, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
            0x00, 0x00, 0x2C, 0x00, 0x01, 0x01, 0x00, 0x00, 0xFD, 0x00, 0x42, 0x03, 0x02, 0x31,
            0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
            0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x31, 0x32,
            0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        ];

        let mut dns_packet_buffer = DNSPacketBuffer::new(&dns_packet_data);
        dns_packet_buffer.seek(HEADER_SIZE);

        let parsed_record = Record::parse_from_buffer(&mut dns_packet_buffer).unwrap();

        let expected_record = Record::new(
            Domain("bar.example.com".to_string()),
            1,
            16777469,
            RecordData::SSHFP(SSHFP {
                algorithm: Algorithm::ECDSA,
                fingerprint_type: FingerprintType::SHA256,
                fingerprint: "123456789abcdef67890123456789abcdef67890123456789abcdef123456789"
                    .to_string(),
            }),
        );

        assert_eq!(parsed_record.preamble.len, 66);
        assert_eq!(parsed_record, expected_record);
    }

    #[test]
    fn test_write_sshfp() {
        let a_record = Record::new(
            Domain("bar.example.com".to_string()),
            1,
            16777469,
            RecordData::SSHFP(SSHFP {
                algorithm: Algorithm::ECDSA,
                fingerprint_type: FingerprintType::SHA256,
                fingerprint: "123456789abcdef67890123456789abcdef67890123456789abcdef123456789"
                    .to_string(),
            }),
        );

        let mut buffer = DNSPacketBuffer::new(&[]);
        buffer.seek(HEADER_SIZE);
        a_record.write_to_buffer(&mut buffer).unwrap();

        // Expected
        let expected_data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x62,
            0x61, 0x72, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
            0x00, 0x00, 0x2C, 0x00, 0x01, 0x01, 0x00, 0x00, 0xFD, 0x00, 0x42, 0x03, 0x02, 0x31,
            0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
            0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x31, 0x32,
            0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        ];

        let mut expected_buffer = DNSPacketBuffer::new(&expected_data);
        expected_buffer.seek(expected_data.len());

        assert_eq!(buffer.get_data(), expected_buffer.get_data())
    }
}
