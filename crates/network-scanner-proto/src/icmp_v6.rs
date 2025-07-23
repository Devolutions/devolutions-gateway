#[repr(u8)]
pub enum Icmpv6MessageType {
    Unreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    EchoRequest = 128,
    EchoReply = 129 
}