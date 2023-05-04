#[derive(Debug, PartialEq, Clone)]
pub enum DNSQueryType {
    A,            // Address record
    AAAA,         // IPv6 address record
    AFSDB,        // AFS database record
    APL,          // Address Prefix List
    CAA,          // Certification Authority Authorization
    CDNSKEY,      // Child copy of DNSKEY record, for transfer to parent
    CDS,          // Child DS
    CERT,         // Certificate record
    CNAME,        // Canonical name record
    CSYNC,        // Child-to-Parent Synchronization
    DHCID,        // DHCP identifier
    DLV,          // DNSSEC Lookaside Validation record
    DNAME,        // Delegation name record
    DNSKEY,       // DNS Key record
    DS,           // Delegation signer
    EUI48,        // MAC address (EUI-48)
    EUI64,        // MAC address (EUI-64)
    HINFO,        // Host Information
    HIP,          // Host Identity Protocol
    HTTPS,        // HTTPS Binding
    IPSECKEY,     // IPsec Key
    KEY,          // Key record
    KX,           // Key Exchanger record
    LOC,          // Location record
    MX,           // Mail exchange record
    NAPTR,        // Naming Authority Pointer
    NS,           // Name server record
    NSEC,         // Next Secure record
    NSEC3,        // Next Secure record version 3
    NSEC3PARAM,   // NSEC3 parameters
    OPENPGPKEY,   // OpenPGP public key record
    PTR,          // PTR Resource Record [de]
    RRSIG,        // DNSSEC signature
    RP,           // Responsible Person
    SIG,          // Signature
    SMIMEA,       // S/MIME cert association[10]
    SOA,          // Start of [a zone of] authority record
    SRV,          // Service locator
    SSHFP,        // SSH Public Key Fingerprint
    SVCB,         // Service Binding
    TA,           // DNSSEC Trust Authorities
    TKEY,         // Transaction Key record
    TLSA,         // TLSA certificate association
    TSIG,         // Transaction Signature
    TXT,          // Text record
    URI,          // Uniform Resource Identifier
    ZONEMD,       // Message Digests for DNS Zones
    Unknown(u16), // Unknown record
}

impl DNSQueryType {
    pub fn from_num(code_num: u16) -> DNSQueryType {
        match code_num {
            1 => DNSQueryType::A,
            28 => DNSQueryType::AAAA,
            18 => DNSQueryType::AFSDB,
            42 => DNSQueryType::APL,
            257 => DNSQueryType::CAA,
            60 => DNSQueryType::CDNSKEY,
            59 => DNSQueryType::CDS,
            37 => DNSQueryType::CERT,
            5 => DNSQueryType::CNAME,
            62 => DNSQueryType::CSYNC,
            49 => DNSQueryType::DHCID,
            32769 => DNSQueryType::DLV,
            39 => DNSQueryType::DNAME,
            48 => DNSQueryType::DNSKEY,
            43 => DNSQueryType::DS,
            108 => DNSQueryType::EUI48,
            109 => DNSQueryType::EUI64,
            13 => DNSQueryType::HINFO,
            55 => DNSQueryType::HIP,
            65 => DNSQueryType::HTTPS,
            45 => DNSQueryType::IPSECKEY,
            25 => DNSQueryType::KEY,
            36 => DNSQueryType::KX,
            29 => DNSQueryType::LOC,
            15 => DNSQueryType::MX,
            35 => DNSQueryType::NAPTR,
            2 => DNSQueryType::NS,
            47 => DNSQueryType::NSEC,
            50 => DNSQueryType::NSEC3,
            51 => DNSQueryType::NSEC3PARAM,
            61 => DNSQueryType::OPENPGPKEY,
            12 => DNSQueryType::PTR,
            46 => DNSQueryType::RRSIG,
            17 => DNSQueryType::RP,
            24 => DNSQueryType::SIG,
            53 => DNSQueryType::SMIMEA,
            6 => DNSQueryType::SOA,
            33 => DNSQueryType::SRV,
            44 => DNSQueryType::SSHFP,
            64 => DNSQueryType::SVCB,
            32768 => DNSQueryType::TA,
            249 => DNSQueryType::TKEY,
            52 => DNSQueryType::TLSA,
            250 => DNSQueryType::TSIG,
            16 => DNSQueryType::TXT,
            256 => DNSQueryType::URI,
            63 => DNSQueryType::ZONEMD,
            _ => DNSQueryType::Unknown(code_num),
        }
    }

    pub fn to_num(&self) -> u16 {
        match self {
            DNSQueryType::A => 1,
            DNSQueryType::AAAA => 28,
            DNSQueryType::AFSDB => 18,
            DNSQueryType::APL => 42,
            DNSQueryType::CAA => 257,
            DNSQueryType::CDNSKEY => 60,
            DNSQueryType::CDS => 59,
            DNSQueryType::CERT => 37,
            DNSQueryType::CNAME => 5,
            DNSQueryType::CSYNC => 62,
            DNSQueryType::DHCID => 49,
            DNSQueryType::DLV => 32769,
            DNSQueryType::DNAME => 39,
            DNSQueryType::DNSKEY => 48,
            DNSQueryType::DS => 43,
            DNSQueryType::EUI48 => 108,
            DNSQueryType::EUI64 => 109,
            DNSQueryType::HINFO => 13,
            DNSQueryType::HIP => 55,
            DNSQueryType::HTTPS => 65,
            DNSQueryType::IPSECKEY => 45,
            DNSQueryType::KEY => 25,
            DNSQueryType::KX => 36,
            DNSQueryType::LOC => 29,
            DNSQueryType::MX => 15,
            DNSQueryType::NAPTR => 35,
            DNSQueryType::NS => 2,
            DNSQueryType::NSEC => 47,
            DNSQueryType::NSEC3 => 50,
            DNSQueryType::NSEC3PARAM => 51,
            DNSQueryType::OPENPGPKEY => 61,
            DNSQueryType::PTR => 12,
            DNSQueryType::RRSIG => 46,
            DNSQueryType::RP => 17,
            DNSQueryType::SIG => 24,
            DNSQueryType::SMIMEA => 53,
            DNSQueryType::SOA => 6,
            DNSQueryType::SRV => 33,
            DNSQueryType::SSHFP => 44,
            DNSQueryType::SVCB => 64,
            DNSQueryType::TA => 32768,
            DNSQueryType::TKEY => 249,
            DNSQueryType::TLSA => 52,
            DNSQueryType::TSIG => 250,
            DNSQueryType::TXT => 16,
            DNSQueryType::URI => 256,
            DNSQueryType::ZONEMD => 63,
            DNSQueryType::Unknown(code) => *code,
        }
    }
}
