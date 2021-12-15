use jmux_proto::*;
use proptest::collection::vec;
use proptest::prelude::*;

pub fn local_channel_id() -> impl Strategy<Value = LocalChannelId> {
    any::<u32>().prop_map(|id| LocalChannelId::from(id))
}

pub fn distant_channel_id() -> impl Strategy<Value = DistantChannelId> {
    any::<u32>().prop_map(|id| DistantChannelId::from(id))
}

pub fn destination_url() -> impl Strategy<Value = DestinationUrl> {
    ("[a-z]{2,4}", "[a-z]{1,10}", any::<u16>())
        .prop_map(|(scheme, host, port)| DestinationUrl::new(&scheme, &host, port))
}

pub fn reason_code() -> impl Strategy<Value = ReasonCode> {
    any::<u32>().prop_map(|code| ReasonCode(code))
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
    (distant_channel_id(), vec(any::<u8>(), 0..512)).prop_map(|(distant_id, data)| Message::data(distant_id, data))
}

pub fn message_eof() -> impl Strategy<Value = Message> {
    distant_channel_id().prop_map(|distant_id| Message::eof(distant_id))
}

pub fn message_close() -> impl Strategy<Value = Message> {
    distant_channel_id().prop_map(|distant_id| Message::close(distant_id))
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
