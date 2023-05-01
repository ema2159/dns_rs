extern crate dns_rs;
use dns_rs::dns_packet::*;
use std::net::UdpSocket;

#[test]
fn stub_resolver_0() {
    let socket = UdpSocket::bind(("0.0.0.0", 43210)).unwrap();

    let google_dns_server = ("8.8.8.8", 53);

    let dns_query_packet = DNSPacket::new(
        DNSHeader {
            id: 0x862a,
            query_response: false,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: true,
            recursion_available: false,
            reserved: 2,
            response_code: DNSResponseCode::NoError,
            question_count: 1,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        },
        Some(vec![DNSQuestion {
            domain: DNSDomain("google.com".to_string()),
            record_type: DNSQueryType::A,
            class: 0x01,
        }]),
        None,
        None,
        None,
    );

    let data_buffer = dns_query_packet.write_dns_packet().unwrap();
    let data = data_buffer.get_data();

    socket.send_to(data, google_dns_server).unwrap();

    let mut recv_data = [0; PACKET_SIZE];

    socket.recv_from(&mut recv_data).unwrap();

    let recv_packet = DNSPacket::parse_dns_packet(&mut DNSPacketBuffer::new(&recv_data));

    println!("{:#?}", recv_packet)
}
