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
