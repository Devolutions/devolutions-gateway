use super::*;

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

    write_tpdu_header(&mut buff, length, code, 0).unwrap();

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

    write_tpdu_header(&mut buff, length, code, 0).unwrap();

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
