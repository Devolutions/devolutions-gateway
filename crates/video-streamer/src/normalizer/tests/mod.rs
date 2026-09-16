use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::thread;
use std::time::Duration;

use super::*;

#[derive(Default)]
struct ReaderStats {
    max_requested: usize,
    read_count: usize,
    seek_count: usize,
    seek_positions: Vec<u64>,
}

struct GrowingReader {
    data: Vec<u8>,
    position: usize,
    visible: Arc<AtomicUsize>,
    stats: Arc<Mutex<ReaderStats>>,
}

impl Read for GrowingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let visible = self.visible.load(Ordering::Acquire).min(self.data.len());
        let available = visible.saturating_sub(self.position);
        let read = available.min(buffer.len());
        if read > 0 {
            buffer[..read].copy_from_slice(&self.data[self.position..self.position + read]);
            self.position += read;
        }
        let mut stats = self.stats.lock().expect("reader stats lock");
        stats.max_requested = stats.max_requested.max(buffer.len());
        stats.read_count += 1;
        Ok(read)
    }
}

impl Seek for GrowingReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(offset) => i64::try_from(offset).map_err(io::Error::other)?,
            SeekFrom::Current(offset) => i64::try_from(self.position)
                .map_err(io::Error::other)?
                .checked_add(offset)
                .ok_or_else(|| io::Error::other("seek overflow"))?,
            SeekFrom::End(offset) => i64::try_from(self.data.len())
                .map_err(io::Error::other)?
                .checked_add(offset)
                .ok_or_else(|| io::Error::other("seek overflow"))?,
        };
        if next < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "negative seek"));
        }
        self.position = usize::try_from(next).map_err(io::Error::other)?;
        let mut stats = self.stats.lock().expect("reader stats lock");
        stats.seek_count += 1;
        stats
            .seek_positions
            .push(u64::try_from(self.position).map_err(io::Error::other)?);
        u64::try_from(self.position).map_err(io::Error::other)
    }
}

fn video_clip_bytes(key_frames: &[bool], block_group: bool) -> Vec<u8> {
    video_clip_bytes_with_group_sizing(key_frames, block_group, false)
}

fn video_clip_bytes_with_group_sizing(key_frames: &[bool], block_group: bool, unknown_block_group: bool) -> Vec<u8> {
    use webm_iterable::matroska_spec::Block;

    let mut writer = WebmWriter::new(Vec::new());
    writer
        .write(&MatroskaSpec::Ebml(Master::Full(vec![
            MatroskaSpec::EbmlVersion(1),
            MatroskaSpec::EbmlReadVersion(1),
            MatroskaSpec::EbmlMaxIdLength(4),
            MatroskaSpec::EbmlMaxSizeLength(8),
            MatroskaSpec::DocType("webm".to_owned()),
            MatroskaSpec::DocTypeVersion(4),
            MatroskaSpec::DocTypeReadVersion(2),
        ])))
        .expect("write EBML header");
    writer
        .write_advanced(
            &MatroskaSpec::Segment(Master::Start),
            WriteOptions::is_unknown_sized_element(),
        )
        .expect("write segment start");
    writer
        .write(&MatroskaSpec::Info(Master::Full(vec![MatroskaSpec::TimestampScale(
            WEBM_TIMESTAMP_SCALE_NS,
        )])))
        .expect("write info");
    writer
        .write(&MatroskaSpec::Tracks(Master::Full(vec![MatroskaSpec::TrackEntry(
            Master::Full(vec![
                MatroskaSpec::TrackNumber(1),
                MatroskaSpec::TrackType(1),
                MatroskaSpec::CodecID("V_VP8".to_owned()),
            ]),
        )])))
        .expect("write video track");
    writer
        .write_advanced(
            &MatroskaSpec::Cluster(Master::Start),
            WriteOptions::is_unknown_sized_element(),
        )
        .expect("write cluster start");
    writer
        .write(&MatroskaSpec::Timestamp(0))
        .expect("write cluster timestamp");

    for (index, &key_frame) in key_frames.iter().enumerate() {
        let frame = if key_frame { [0] } else { [1] };
        let timestamp = i16::try_from(index * 30).expect("test timestamp fits");
        if block_group {
            if unknown_block_group {
                writer
                    .write_advanced(
                        &MatroskaSpec::BlockGroup(Master::Start),
                        WriteOptions::is_unknown_sized_element(),
                    )
                    .expect("write unknown-sized block group start");
            } else {
                writer
                    .write(&MatroskaSpec::BlockGroup(Master::Start))
                    .expect("write block group start");
            }
            writer
                .write(&MatroskaSpec::from(Block::new_uncheked(
                    1, timestamp, false, None, &frame,
                )))
                .expect("write block");
            writer
                .write(&MatroskaSpec::BlockGroup(Master::End))
                .expect("write block group end");
        } else {
            writer
                .write(&MatroskaSpec::from(SimpleBlock::new_uncheked(
                    &frame, 1, timestamp, false, None, false, key_frame,
                )))
                .expect("write simple block");
        }
    }

    if block_group {
        writer
            .write(&MatroskaSpec::Timestamp(1))
            .expect("write block group terminator");
    }

    writer.into_inner().expect("finish video clip bytes")
}

fn truncate_inside_block_payload(data: &[u8], block_index: usize) -> Vec<u8> {
    let mut decoder = TagDecoder::new(&[]);
    let mut input = BytesMut::from(data);
    let mut current_index = 0;
    while let Some(positioned) = decoder.decode(&mut input).expect("decode complete fixture") {
        if matches!(positioned.tag, MatroskaSpec::Block(_)) {
            if current_index == block_index {
                let block_end = decoder.position();
                let mut truncated = data.to_vec();
                truncated.truncate(block_end.checked_sub(1).expect("block payload is nonempty"));
                return truncated;
            }
            current_index += 1;
        }
    }
    panic!("fixture does not contain requested block");
}

fn truncate_before_last_timestamp(data: &[u8]) -> Vec<u8> {
    let mut decoder = TagDecoder::new(&[]);
    let mut input = BytesMut::from(data);
    let mut last_timestamp_start = None;
    while let Some(positioned) = decoder.decode(&mut input).expect("decode complete fixture") {
        if matches!(positioned.tag, MatroskaSpec::Timestamp(_)) {
            last_timestamp_start = Some(positioned.offset);
        }
    }
    let timestamp_start = last_timestamp_start.expect("fixture has a timestamp terminator");
    data[..timestamp_start].to_vec()
}

fn live_edge_normalizer<R>(reader: R) -> (ClipNormalizer, mpsc::Receiver<anyhow::Result<SegmentEvent>>)
where
    R: Read + Seek + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(8);
    let normalizer = ClipNormalizer::new(
        0,
        StartAt::LiveEdge,
        RecordingClip::new(reader),
        sender,
        SessionConfig { encoder_threads: 1 },
        0,
    )
    .expect("create live-edge normalizer");
    (normalizer, receiver)
}

fn empty_clip_bytes() -> Vec<u8> {
    let mut writer = WebmWriter::new(Vec::new());
    writer
        .write(&MatroskaSpec::Ebml(Master::Full(vec![
            MatroskaSpec::EbmlVersion(1),
            MatroskaSpec::EbmlReadVersion(1),
            MatroskaSpec::EbmlMaxIdLength(4),
            MatroskaSpec::EbmlMaxSizeLength(8),
            MatroskaSpec::DocType("webm".to_owned()),
            MatroskaSpec::DocTypeVersion(4),
            MatroskaSpec::DocTypeReadVersion(2),
        ])))
        .expect("write EBML header");
    writer
        .write_advanced(
            &MatroskaSpec::Segment(Master::Start),
            WriteOptions::is_unknown_sized_element(),
        )
        .expect("write segment start");
    writer
        .write_advanced(
            &MatroskaSpec::Cluster(Master::Start),
            WriteOptions::is_unknown_sized_element(),
        )
        .expect("write cluster start");
    writer
        .write(&MatroskaSpec::Timestamp(0))
        .expect("write cluster timestamp");
    writer.into_inner().expect("finish clip bytes")
}

mod replay;

#[test]
fn resolution_change_starts_the_next_output_segment() {
    let first_dimensions = Dimensions {
        width: 640,
        height: 480,
    };
    let second_dimensions = Dimensions {
        width: 1280,
        height: 720,
    };

    assert_eq!(
        next_segment_info(None, first_dimensions, 0),
        Some(SegmentInfo {
            sequence: 0,
            width: 640,
            height: 480,
        })
    );
    assert_eq!(next_segment_info(Some(first_dimensions), first_dimensions, 1), None);
    assert_eq!(
        next_segment_info(Some(first_dimensions), second_dimensions, 1),
        Some(SegmentInfo {
            sequence: 1,
            width: 1280,
            height: 720,
        })
    );
}

#[test]
fn scanner_uses_bounded_reads_and_constant_replay_metadata() {
    let data = video_clip_bytes(&[true, false, false, true, false], false);
    let visible = Arc::new(AtomicUsize::new(data.len()));
    let stats = Arc::new(Mutex::new(ReaderStats::default()));
    let reader = GrowingReader {
        data,
        position: 0,
        visible,
        stats: Arc::clone(&stats),
    };
    let (mut normalizer, _receiver) = live_edge_normalizer(reader);

    normalizer.scan_available().expect("scan available history");

    let stats = stats.lock().expect("reader stats lock");
    assert!(stats.max_requested <= INPUT_CHUNK_SIZE);
    assert_eq!(stats.seek_count, 1);
    assert!(normalizer.input.is_empty());
    assert!(normalizer.replay_point.is_some());
    assert!(normalizer.complete_boundary > normalizer.replay_point.expect("replay point").block_offset);
}

#[test]
fn incomplete_simple_block_continues_once_when_reader_grows() {
    let data = video_clip_bytes(&[true], false);
    let visible = Arc::new(AtomicUsize::new(data.len() - 1));
    let reader = GrowingReader {
        data: data.clone(),
        position: 0,
        visible: Arc::clone(&visible),
        stats: Arc::new(Mutex::new(ReaderStats::default())),
    };
    let (mut normalizer, _receiver) = live_edge_normalizer(reader);

    normalizer.scan_available().expect("scan partial simple block");
    assert!(normalizer.replay_point.is_none());

    visible.store(data.len(), Ordering::Release);
    normalizer.scan_available().expect("continue simple block");
    assert!(normalizer.replay_point.is_some());
    assert_eq!(
        normalizer.complete_boundary,
        u64::try_from(data.len()).expect("fixture length fits")
    );
}

#[test]
fn incomplete_block_group_does_not_become_a_replay_boundary() {
    let data = video_clip_bytes(&[true], true);
    let partial = truncate_inside_block_payload(&data, 0);
    let visible = Arc::new(AtomicUsize::new(partial.len()));
    let reader = GrowingReader {
        data: data.clone(),
        position: 0,
        visible: Arc::clone(&visible),
        stats: Arc::new(Mutex::new(ReaderStats::default())),
    };
    let (mut normalizer, _receiver) = live_edge_normalizer(reader);

    normalizer.scan_available().expect("scan partial block group");
    assert!(normalizer.replay_point.is_none());
    assert_eq!(normalizer.complete_boundary, 0);

    visible.store(data.len(), Ordering::Release);
    normalizer.scan_available().expect("continue block group");
    assert!(normalizer.replay_point.is_some());
    assert!(normalizer.complete_boundary > 0);
}

#[test]
fn oversized_element_is_rejected_before_unbounded_capture() {
    let oversized = vec![0xa3, 0x14, 0x00, 0x00, 0x01];
    let (mut normalizer, _receiver) = live_edge_normalizer(Cursor::new(oversized));

    assert!(normalizer.scan_available().is_err());
}

#[test]
fn output_data_events_are_bounded() {
    let (sender, mut receiver) = mpsc::channel(4);
    let mut writer = EventWriter { sender };
    let data = vec![0; OUTPUT_CHUNK_SIZE * 2 + 1];

    assert_eq!(writer.write(&data).expect("write output data"), data.len());
    for expected_len in [OUTPUT_CHUNK_SIZE, OUTPUT_CHUNK_SIZE, 1] {
        let event = receiver
            .blocking_recv()
            .expect("receive output data")
            .expect("output event");
        let SegmentEvent::Data(data) = event else {
            panic!("unexpected output event");
        };
        assert_eq!(data.len(), expected_len);
    }
}

#[test]
fn output_prefetch_is_bounded_and_refills_in_order() {
    let (sender, mut receiver) = mpsc::channel(OUTPUT_CHANNEL_CAPACITY);
    let mut writer = EventWriter { sender };
    let (partial_ready_sender, partial_ready_receiver) = std_mpsc::channel();
    let (prefetch_release_sender, prefetch_release_receiver) = std_mpsc::channel();
    let (prefetch_ready_sender, prefetch_ready_receiver) = std_mpsc::channel();
    let (refill_started_sender, refill_started_receiver) = std_mpsc::channel();
    let (finished_sender, finished_receiver) = std_mpsc::channel();
    let producer = thread::spawn(move || {
        writer.write_all(b"partial").expect("write partial output");
        partial_ready_sender.send(()).expect("signal partial output");
        prefetch_release_receiver.recv().expect("release prefetch");

        let mut prefetched = Vec::with_capacity(OUTPUT_CHANNEL_CAPACITY * OUTPUT_CHUNK_SIZE);
        for marker in 1..=OUTPUT_CHANNEL_CAPACITY {
            prefetched.extend(std::iter::repeat_n(
                u8::try_from(marker).expect("marker fits in u8"),
                OUTPUT_CHUNK_SIZE,
            ));
        }
        writer.write_all(&prefetched).expect("write prefetched output");
        prefetch_ready_sender.send(()).expect("signal full prefetch");

        refill_started_sender.send(()).expect("signal refill attempt");
        let mut refill = Vec::with_capacity(2 * OUTPUT_CHUNK_SIZE);
        for marker in OUTPUT_CHANNEL_CAPACITY + 1..=OUTPUT_CHANNEL_CAPACITY + 2 {
            refill.extend(std::iter::repeat_n(
                u8::try_from(marker).expect("marker fits in u8"),
                OUTPUT_CHUNK_SIZE,
            ));
        }
        writer.write_all(&refill).expect("write refill output");
        finished_sender.send(()).expect("signal producer completion");
    });

    partial_ready_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("partial output was not ready");
    assert_eq!(receiver.len(), 1);
    let partial = receiver
        .try_recv()
        .expect("receive partial output")
        .expect("partial output event");
    assert_eq!(partial, SegmentEvent::Data(Bytes::from_static(b"partial")));

    prefetch_release_sender.send(()).expect("release prefetch");
    prefetch_ready_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("prefetch did not fill");
    assert_eq!(receiver.len(), OUTPUT_CHANNEL_CAPACITY);
    assert_eq!(receiver.len() * OUTPUT_CHUNK_SIZE, 256 * 1024);
    refill_started_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("refill did not start");
    assert!(matches!(
        finished_receiver.recv_timeout(Duration::from_millis(25)),
        Err(std_mpsc::RecvTimeoutError::Timeout)
    ));

    for expected_marker in 1..=OUTPUT_CHANNEL_CAPACITY {
        let event = receiver
            .try_recv()
            .expect("receive prefetched output")
            .expect("prefetched output event");
        let SegmentEvent::Data(data) = event else {
            panic!("unexpected output event");
        };
        assert_eq!(data.len(), OUTPUT_CHUNK_SIZE);
        let expected_marker = u8::try_from(expected_marker).expect("marker fits in u8");
        assert!(data.iter().all(|&byte| byte == expected_marker));
    }
    finished_receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("producer did not finish after consumption");
    for expected_marker in OUTPUT_CHANNEL_CAPACITY + 1..=OUTPUT_CHANNEL_CAPACITY + 2 {
        let event = receiver
            .try_recv()
            .expect("receive refilled output")
            .expect("refilled output event");
        let SegmentEvent::Data(data) = event else {
            panic!("unexpected output event");
        };
        assert_eq!(data.len(), OUTPUT_CHUNK_SIZE);
        let expected_marker = u8::try_from(expected_marker).expect("marker fits in u8");
        assert!(data.iter().all(|&byte| byte == expected_marker));
    }
    producer.join().expect("producer thread panicked");
}

#[test]
fn truncated_clip_tail_does_not_abort_the_following_clip() {
    let mut truncated = empty_clip_bytes();
    truncated.extend_from_slice(&[0xa3, 0x84, 0x81, 0x00]);
    let complete = empty_clip_bytes();
    let events = vec![
        RecordingEvent::ClipStarted {
            sequence: 0,
            start_at: StartAt::Beginning,
            clip: RecordingClip::new(Cursor::new(truncated)),
        },
        RecordingEvent::CaughtUp,
        RecordingEvent::ClipEnded,
        RecordingEvent::ClipStarted {
            sequence: 1,
            start_at: StartAt::Beginning,
            clip: RecordingClip::new(Cursor::new(complete)),
        },
        RecordingEvent::CaughtUp,
        RecordingEvent::ClipEnded,
        RecordingEvent::SessionEnded,
    ];
    let (input_sender, input_receiver) = mpsc::channel(events.len());
    for event in events {
        input_sender.blocking_send(Ok(event)).expect("queue recording event");
    }
    drop(input_sender);
    let (output_sender, mut output_receiver) = mpsc::channel(1);

    normalize_events(input_receiver, output_sender, SessionConfig { encoder_threads: 1 })
        .expect("normalize reconnecting clips");
    assert!(output_receiver.blocking_recv().is_none());
}

#[test]
fn corruption_before_an_incomplete_tail_still_fails() {
    let mut corrupted = empty_clip_bytes();
    corrupted.extend_from_slice(&[0xff, 0x80]);
    corrupted.extend_from_slice(&[0xa3, 0x84, 0x81, 0x00]);
    let events = vec![
        RecordingEvent::ClipStarted {
            sequence: 0,
            start_at: StartAt::Beginning,
            clip: RecordingClip::new(Cursor::new(corrupted)),
        },
        RecordingEvent::CaughtUp,
        RecordingEvent::ClipEnded,
        RecordingEvent::SessionEnded,
    ];
    let (input_sender, input_receiver) = mpsc::channel(events.len());
    for event in events {
        input_sender.blocking_send(Ok(event)).expect("queue recording event");
    }
    drop(input_sender);
    let (output_sender, _output_receiver) = mpsc::channel(1);

    let error = normalize_events(input_receiver, output_sender, SessionConfig { encoder_threads: 1 })
        .expect_err("corruption before the incomplete tail must fail");

    assert!(format!("{error:#}").contains("corrupted"), "{error:#}");
}
