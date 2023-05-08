#[derive(Debug, PartialEq, Clone)]
pub enum QueryType {
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

impl QueryType {
    pub fn from_num(code_num: u16) -> QueryType {
        match code_num {
            1 => QueryType::A,
            28 => QueryType::AAAA,
            18 => QueryType::AFSDB,
            42 => QueryType::APL,
            257 => QueryType::CAA,
            60 => QueryType::CDNSKEY,
            59 => QueryType::CDS,
            37 => QueryType::CERT,
            5 => QueryType::CNAME,
            62 => QueryType::CSYNC,
            49 => QueryType::DHCID,
            32769 => QueryType::DLV,
            39 => QueryType::DNAME,
            48 => QueryType::DNSKEY,
            43 => QueryType::DS,
            108 => QueryType::EUI48,
            109 => QueryType::EUI64,
            13 => QueryType::HINFO,
            55 => QueryType::HIP,
            65 => QueryType::HTTPS,
            45 => QueryType::IPSECKEY,
            25 => QueryType::KEY,
            36 => QueryType::KX,
            29 => QueryType::LOC,
            15 => QueryType::MX,
            35 => QueryType::NAPTR,
            2 => QueryType::NS,
            47 => QueryType::NSEC,
            50 => QueryType::NSEC3,
            51 => QueryType::NSEC3PARAM,
            61 => QueryType::OPENPGPKEY,
            12 => QueryType::PTR,
            46 => QueryType::RRSIG,
            17 => QueryType::RP,
            24 => QueryType::SIG,
            53 => QueryType::SMIMEA,
            6 => QueryType::SOA,
            33 => QueryType::SRV,
            44 => QueryType::SSHFP,
            64 => QueryType::SVCB,
            32768 => QueryType::TA,
            249 => QueryType::TKEY,
            52 => QueryType::TLSA,
            250 => QueryType::TSIG,
            16 => QueryType::TXT,
            256 => QueryType::URI,
            63 => QueryType::ZONEMD,
            _ => QueryType::Unknown(code_num),
        }
    }

    pub fn to_num(&self) -> u16 {
        match self {
            QueryType::A => 1,
            QueryType::AAAA => 28,
            QueryType::AFSDB => 18,
            QueryType::APL => 42,
            QueryType::CAA => 257,
            QueryType::CDNSKEY => 60,
            QueryType::CDS => 59,
            QueryType::CERT => 37,
            QueryType::CNAME => 5,
            QueryType::CSYNC => 62,
            QueryType::DHCID => 49,
            QueryType::DLV => 32769,
            QueryType::DNAME => 39,
            QueryType::DNSKEY => 48,
            QueryType::DS => 43,
            QueryType::EUI48 => 108,
            QueryType::EUI64 => 109,
            QueryType::HINFO => 13,
            QueryType::HIP => 55,
            QueryType::HTTPS => 65,
            QueryType::IPSECKEY => 45,
            QueryType::KEY => 25,
            QueryType::KX => 36,
            QueryType::LOC => 29,
            QueryType::MX => 15,
            QueryType::NAPTR => 35,
            QueryType::NS => 2,
            QueryType::NSEC => 47,
            QueryType::NSEC3 => 50,
            QueryType::NSEC3PARAM => 51,
            QueryType::OPENPGPKEY => 61,
            QueryType::PTR => 12,
            QueryType::RRSIG => 46,
            QueryType::RP => 17,
            QueryType::SIG => 24,
            QueryType::SMIMEA => 53,
            QueryType::SOA => 6,
            QueryType::SRV => 33,
            QueryType::SSHFP => 44,
            QueryType::SVCB => 64,
            QueryType::TA => 32768,
            QueryType::TKEY => 249,
            QueryType::TLSA => 52,
            QueryType::TSIG => 250,
            QueryType::TXT => 16,
            QueryType::URI => 256,
            QueryType::ZONEMD => 63,
            QueryType::Unknown(code) => *code,
        }
    }
}
