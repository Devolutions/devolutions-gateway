use jmux_proto::*;
use proptest::collection::vec;
use proptest::prelude::*;

pub fn local_channel_id() -> impl Strategy<Value = LocalChannelId> {
    any::<u32>().prop_map(LocalChannelId::from)
}

pub fn distant_channel_id() -> impl Strategy<Value = DistantChannelId> {
    any::<u32>().prop_map(DistantChannelId::from)
}

pub fn destination_url_parts() -> impl Strategy<Value = (String, String, u16)> {
    (".{1,5}", ".{1,10}", any::<u16>())
}

pub fn destination_url() -> impl Strategy<Value = DestinationUrl> {
    destination_url_parts().prop_map(|(scheme, host, port)| DestinationUrl::new(&scheme, &host, port))
}

pub fn reason_code() -> impl Strategy<Value = ReasonCode> {
    any::<u32>().prop_map(ReasonCode)
}

pub fn message_open() -> impl Strategy<Value = Message> {
    (local_channel_id(), any::<u16>(), destination_url())
        .prop_map(|(id, max_packet_size, url)| Message::open(id, max_packet_size, url))
}

pub fn message_open_success() -> impl Strategy<Value = Message> {
    (distant_channel_id(), local_channel_id(), any::<u32>(), any::<u16>()).prop_map(
        |(distant_id, local_id, initial_win_size, max_packet_size)| {
            Message::open_success(distant_id, local_id, initial_win_size, max_packet_size)
        },
    )
}

pub fn message_open_failure() -> impl Strategy<Value = Message> {
    (distant_channel_id(), reason_code(), ".{0,512}")
        .prop_map(|(distant_id, reason_code, desc)| Message::open_failure(distant_id, reason_code, desc))
}

pub fn message_window_adjust() -> impl Strategy<Value = Message> {
    (distant_channel_id(), any::<u32>())
        .prop_map(|(distant_id, window_adjustment)| Message::window_adjust(distant_id, window_adjustment))
}

pub fn message_data() -> impl Strategy<Value = Message> {
    (distant_channel_id(), vec(any::<u8>(), 0..512))
        .prop_map(|(distant_id, data)| Message::data(distant_id, Bytes::from(data)))
}

pub fn message_eof() -> impl Strategy<Value = Message> {
    distant_channel_id().prop_map(Message::eof)
}

pub fn message_close() -> impl Strategy<Value = Message> {
    distant_channel_id().prop_map(Message::close)
}

pub fn any_message() -> impl Strategy<Value = Message> {
    prop_oneof![
        message_close(),
        message_eof(),
        message_window_adjust(),
        message_open_success(),
        message_open_failure(),
        message_open(),
        message_data(),
    ]
}
