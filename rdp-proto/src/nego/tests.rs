use num_traits::ToPrimitive;

use super::*;

#[test]
fn cookie_is_written_to_request() {
    let mut buff = Vec::new();
    let settings = Settings {
        username: "a".to_string(),
        security_protocol: SecurityProtocol::NLA,
    };
    let expected = [
        0x43, 0x6F, 0x6F, 0x6B, 0x69, 0x65, 0x3A, 0x20, 0x6D, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3D, 0x61,
        0x0D, 0x0A,
    ];

    send_negotiation_request(&mut buff, &settings).unwrap();

    assert_eq!(
        buff[TPDU_CONNECTION_REQUEST_LENGTH..TPDU_CONNECTION_REQUEST_LENGTH + expected.len()],
        expected
    );
}

#[test]
fn rdp_negotiation_data_is_written_to_request() {
    let mut buff = Vec::new();
    let settings = Settings {
        username: "a".to_string(),
        security_protocol: SecurityProtocol::NLA,
    };
    let expected = [0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00];

    let written = send_negotiation_request(&mut buff, &settings).unwrap() as usize;

    assert_eq!(buff[written - 8..written], expected);
}

#[test]
fn rdp_negotiation_data_is_not_written_if_rdp_security() {
    let mut buff = Vec::new();
    let settings = Settings {
        username: "a".to_string(),
        security_protocol: SecurityProtocol::RDP,
    };
    let cookie_len = 20;

    let written = send_negotiation_request(&mut buff, &settings).unwrap() as usize;

    assert_eq!(written, TPDU_CONNECTION_REQUEST_LENGTH + cookie_len);
}

#[test]
fn tpkt_and_tpdu_headers_are_written_to_request() {
    let mut buff = Vec::new();
    let settings = Settings {
        username: "User".to_string(),
        security_protocol: SecurityProtocol::NLA,
    };
    let expected = [0x03, 0x00, 0x00, 0x2A, 0x25, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00];

    send_negotiation_request(&mut buff, &settings).unwrap();

    assert_eq!(buff[0..TPDU_CONNECTION_REQUEST_LENGTH], expected);
}

#[test]
fn negotiation_request_is_written_correclty() {
    let expected: &[u8] = &[
        0x03, 0x00, 0x00, 0x2A, 0x25, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x6F, 0x6F, 0x6B, 0x69, 0x65, 0x3A,
        0x20, 0x6D, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3D, 0x55, 0x73, 0x65, 0x72, 0x0D, 0x0A, 0x01, 0x00,
        0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
    ];
    let mut buff = Vec::new();
    let settings = Settings {
        username: "User".to_string(),
        security_protocol: SecurityProtocol::NLA,
    };

    send_negotiation_request(&mut buff, &settings).unwrap();

    assert_eq!(buff, expected);
}

#[test]
fn tpkt_header_is_written_correctly() {
    let expected = [
        0x3, // version
        0x0, // reserved
        0x5, 0x42, // lenght in BE
    ];
    let mut buff = Vec::new();

    write_tpkt_header(&mut buff, 1346).unwrap();

    assert_eq!(buff, expected);
}

#[test]
fn tpkt_pdu_is_read_correctly() {
    let tpkt_header = vec![0x3, 0x0, 0x0, 0x9];
    let data = [0x1, 0x2, 0x3, 0x4, 0x5];
    let noise = [0xff, 0xff, 0xff];
    let mut stream = tpkt_header;
    stream.extend(&data);
    stream.extend(&noise);
    let mut buff = Vec::new();

    read_tpkt_pdu(&mut buff, &mut stream.as_slice()).unwrap();

    assert_eq!(buff, data);
}

#[test]
fn read_tpkt_pdu_returns_error_on_invalid_pdu() {
    let stream = [0x1, 0x0, 0x0, 0x9];
    let mut buff = Vec::new();

    match read_tpkt_pdu(&mut buff, &mut stream.as_ref()) {
        Err(ref e) if e.kind() == io::ErrorKind::InvalidData => (),
        Err(_) => panic!("read_tpkt_pdu returned wrong error type"),
        _ => panic!("read_tpkt_pdu was suposed to return an error"),
    }
}

#[test]
fn read_tpkt_pdu_returns_error_on_partial_pdu() {
    let stream = [0x3, 0x0, 0x0, 0x9, 0x1, 0x2];
    let mut buff = Vec::new();

    match read_tpkt_pdu(&mut buff, &mut stream.as_ref()) {
        Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => (),
        Err(_) => panic!("wrong error type"),
        _ => panic!("error expected"),
    }
}

#[test]
fn tpdu_header_non_data_is_written_correctly() {
    let length = 0x42;
    let code = X224TPDUType::ConnectionRequest;
    let expected = [
        length - 1,
        code.to_u8().unwrap(),
        0x0,
        0x0, // DST-REF
        0x0,
        0x0, // SRC-REF
        0x0, // Class 0
    ];
    let mut buff = Vec::new();

    write_tpdu_header(&mut buff, length, code).unwrap();

    assert_eq!(buff, expected);
}

#[test]
fn tpdu_header_data_is_written_correctly() {
    let length = 0x42;
    let code = X224TPDUType::Data;
    let expected = [
        length - 1,
        code.to_u8().unwrap(),
        0x80, // EOT
    ];
    let mut buff = Vec::new();

    write_tpdu_header(&mut buff, length, code).unwrap();

    assert_eq!(buff, expected);
}

#[test]
fn tpdu_code_and_len_are_read_correctly() {
    let expected_length = 0x42;
    let expected_code = X224TPDUType::ConnectionRequest;
    let stream = [
        expected_length,
        expected_code.to_u8().unwrap(),
        0x0,
        0x0, // DST-REF
        0x0,
        0x0, // SRC-REF
        0x0, // Class 0
    ];

    let (length, code) = parse_tdpu_header(&mut stream.as_ref()).unwrap();

    assert_eq!(length, expected_length);
    assert_eq!(code, expected_code);
}

#[test]
fn parse_tdpu_non_data_header_advance_stream_position() {
    let expected_length = 0x42;
    let expected_code = X224TPDUType::ConnectionRequest;
    let stream = [
        expected_length,
        expected_code.to_u8().unwrap(),
        0x0,
        0x0, // DST-REF
        0x0,
        0x0, // SRC-REF
        0x0, // Class 0
        0xbf,
    ];
    let mut slice = stream.as_ref();

    parse_tdpu_header(&mut slice).unwrap();

    let next = slice.read_u8().unwrap();
    assert_eq!(next, 0xbf);
}

#[test]
fn parse_tdpu_data_header_advance_stream_position() {
    let expected_length = 0x42;
    let expected_code = X224TPDUType::Data;
    let stream = [
        expected_length,
        expected_code.to_u8().unwrap(),
        0x80, // EOT
        0xbf,
    ];
    let mut slice = stream.as_ref();

    parse_tdpu_header(&mut slice).unwrap();

    let next = slice.read_u8().unwrap();
    assert_eq!(next, 0xbf);
}

#[test]
fn negotiation_response_is_processed_correctly() {
    let stream = [
        0x03, 0x00, 0x00, 0x13, // tpkt header
        0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00, // tpdu header
        0x02, // negotiation message
        0x1F, // flags
        0x08, 0x00, // length
        0x02, 0x00, 0x00, 0x00, // selected protocol
    ];

    let selected_protocol = receive_nego_response(&mut stream.as_ref()).unwrap();

    assert_eq!(selected_protocol, SecurityProtocol::Hybrid);
}

#[test]
fn truncated_negotiation_response_results_in_error() {
    let stream = [
        0x03, 0x00, 0x00, 0x0B, // tpkt header
        0x06, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00, // tpdu header
    ];

    match receive_nego_response(&mut stream.as_ref()) {
        Err(NegotiationError::IOError(ref e)) if e.kind() == io::ErrorKind::InvalidData => (),
        Err(_) => panic!("wrong error type"),
        _ => panic!("error expected"),
    }
}

#[test]
fn wrong_x224_code_in_negotiation_response_results_in_error() {
    let stream = [
        0x03, 0x00, 0x00, 0x13, // tpkt header
        0x0E, 0x70, 0x00, 0x00, 0x12, 0x34, 0x00, // tpdu header
        0x02, // negotiation message
        0x1F, // flags
        0x08, 0x00, // length
        0x02, 0x00, 0x00, 0x00, // selected protocol
    ];

    match receive_nego_response(&mut stream.as_ref()) {
        Err(NegotiationError::IOError(ref e)) if e.kind() == io::ErrorKind::InvalidData => (),
        Err(_) => panic!("wrong error type"),
        _ => panic!("error expected"),
    }
}

#[test]
fn wrong_message_code_in_negotiation_response_results_in_error() {
    let stream = [
        0x03, 0x00, 0x00, 0x13, // tpkt header
        0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00, // tpdu header
        0xAF, // negotiation message
        0x1F, // flags
        0x08, 0x00, // length
        0x02, 0x00, 0x00, 0x00, // selected protocol
    ];

    match receive_nego_response(&mut stream.as_ref()) {
        Err(NegotiationError::IOError(ref e)) if e.kind() == io::ErrorKind::InvalidData => (),
        Err(_) => panic!("wrong error type"),
        _ => panic!("error expected"),
    }
}

#[test]
fn negotiation_failure_in_repsonse_results_in_error() {
    let stream = [
        0x03, 0x00, 0x00, 0x13, // tpkt header
        0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00, // tpdu header
        0x03, // negotiation message
        0x1F, // flags
        0x08, 0x00, // length
        0x06, 0x00, 0x00, 0x00, // failure code
    ];

    match receive_nego_response(&mut stream.as_ref()) {
        Err(NegotiationError::NegotiationFailure(e)) if e == 0x06 => (),
        Err(_) => panic!("wrong error type"),
        _ => panic!("error expected"),
    }
}
