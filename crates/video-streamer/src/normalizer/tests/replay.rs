use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use webm_iterable::matroska_spec::{Master, MatroskaSpec, SimpleBlock};
use webm_iterable::{WebmWriter, WriteOptions};

use super::*;

#[test]
fn replay_uses_latest_gop_and_restores_the_same_reader() {
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
    let original_head = normalizer.reader_head;
    let replay_point = normalizer.replay_point.expect("latest replay point");
    let mut frames = Vec::new();
    let mut process_frame = |_: &mut ClipNormalizer, frame: PendingFrame| {
        frames.push((frame.timestamp, frame.key_frame));
        Ok(())
    };

    normalizer
        .caught_up_with(&mut process_frame)
        .expect("replay latest GOP");

    assert_eq!(frames, vec![(90, true), (120, false)]);
    assert_eq!(normalizer.reader_head, original_head);

    let stats = stats.lock().expect("reader stats lock");
    assert_eq!(stats.seek_positions.first(), Some(&0));
    assert_eq!(stats.seek_positions.get(1), Some(&replay_point.block_offset));
    assert_eq!(stats.seek_positions.last(), Some(&original_head));
}

#[test]
fn replay_error_restores_the_original_parser_and_reader_state() {
    let data = video_clip_bytes(&[true, false, true], false);
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
    let original_head = normalizer.reader_head;
    let original_decoder_position = normalizer.decoder.position();
    let original_input = normalizer.input.clone();
    let mut process_frame = |_: &mut ClipNormalizer, _: PendingFrame| Err(anyhow::anyhow!("replay callback failed"));

    let error = normalizer
        .caught_up_with(&mut process_frame)
        .expect_err("replay callback failure");

    assert!(format!("{error:#}").contains("replay callback failed"));
    assert_eq!(normalizer.reader_head, original_head);
    assert_eq!(normalizer.decoder.position(), original_decoder_position);
    assert_eq!(normalizer.input, original_input);

    let stats = stats.lock().expect("reader stats lock");
    assert_eq!(stats.seek_positions.last(), Some(&original_head));
}

#[test]
fn known_size_group_replay_excludes_a_partial_next_group_until_growth() {
    let data = video_clip_bytes(&[true, true], true);
    let partial = truncate_inside_block_payload(&data, 1);
    let visible = Arc::new(AtomicUsize::new(partial.len()));
    let reader = GrowingReader {
        data: data.clone(),
        position: 0,
        visible: Arc::clone(&visible),
        stats: Arc::new(Mutex::new(ReaderStats::default())),
    };
    let (mut normalizer, _receiver) = live_edge_normalizer(reader);
    let mut frames = Vec::new();

    normalizer.scan_available().expect("scan partial group");
    assert!(normalizer.pending_block_group.is_some());
    {
        let mut process_frame = |_: &mut ClipNormalizer, frame: PendingFrame| {
            frames.push((frame.timestamp, frame.key_frame));
            Ok(())
        };
        normalizer
            .caught_up_with(&mut process_frame)
            .expect("replay complete group");
    }
    assert_eq!(frames, vec![(0, true)]);

    visible.store(data.len(), Ordering::Release);
    let mut process_frame = |_: &mut ClipNormalizer, frame: PendingFrame| {
        frames.push((frame.timestamp, frame.key_frame));
        Ok(())
    };
    normalizer
        .scan_available_with(&mut process_frame)
        .expect("consume grown group");
    assert_eq!(frames, vec![(0, true), (30, true)]);
}

#[test]
fn unknown_size_group_replay_uses_the_following_sibling_as_its_boundary() {
    let data = video_clip_bytes_with_group_sizing(&[true, true], true, true);
    let partial = truncate_before_last_timestamp(&data);
    let visible = Arc::new(AtomicUsize::new(partial.len()));
    let reader = GrowingReader {
        data: data.clone(),
        position: 0,
        visible: Arc::clone(&visible),
        stats: Arc::new(Mutex::new(ReaderStats::default())),
    };
    let (mut normalizer, _receiver) = live_edge_normalizer(reader);
    let mut frames = Vec::new();

    normalizer.scan_available().expect("scan unknown-sized group");
    assert!(normalizer.pending_block_group.is_some());
    {
        let mut process_frame = |_: &mut ClipNormalizer, frame: PendingFrame| {
            frames.push((frame.timestamp, frame.key_frame));
            Ok(())
        };
        normalizer
            .caught_up_with(&mut process_frame)
            .expect("replay through the complete boundary");
    }
    assert_eq!(frames, vec![(0, true)]);

    visible.store(data.len(), Ordering::Release);
    let mut process_frame = |_: &mut ClipNormalizer, frame: PendingFrame| {
        frames.push((frame.timestamp, frame.key_frame));
        Ok(())
    };
    normalizer
        .scan_available_with(&mut process_frame)
        .expect("consume following sibling");
    assert_eq!(frames, vec![(0, true), (30, true)]);
}

#[test]
fn replay_stops_at_a_completed_frame_inside_a_known_cluster() {
    let data = cross_cluster_replay_bytes();
    let visible = Arc::new(AtomicUsize::new(data.len() - 1));
    let reader = GrowingReader {
        data,
        position: 0,
        visible,
        stats: Arc::new(Mutex::new(ReaderStats::default())),
    };
    let (mut normalizer, _receiver) = live_edge_normalizer(reader);
    let mut frames = Vec::new();
    let mut process_frame = |_: &mut ClipNormalizer, frame: PendingFrame| {
        frames.push((frame.timestamp, frame.key_frame));
        Ok(())
    };

    normalizer.scan_available().expect("scan cross-cluster history");
    normalizer
        .caught_up_with(&mut process_frame)
        .expect("replay completed frames without finalizing the document");

    assert_eq!(frames, vec![(0, true), (30, false)]);
}

#[test]
fn closed_output_stops_scan_at_a_frame_checkpoint() {
    let data = video_clip_bytes(&[true, false, false], false);
    let visible = Arc::new(AtomicUsize::new(data.len()));
    let stats = Arc::new(Mutex::new(ReaderStats::default()));
    let reader = GrowingReader {
        data,
        position: 0,
        visible,
        stats: Arc::clone(&stats),
    };
    let (sender, mut receiver) = mpsc::channel(8);
    let mut normalizer = ClipNormalizer::new(
        0,
        StartAt::Beginning,
        RecordingClip::new(reader),
        sender,
        SessionConfig { encoder_threads: 1 },
        0,
    )
    .expect("create beginning normalizer");
    let mut process_frame = |_: &mut ClipNormalizer, _: PendingFrame| {
        receiver.close();
        Ok(())
    };

    normalizer
        .scan_available_with(&mut process_frame)
        .expect("stop scan after receiver closes");

    let stats = stats.lock().expect("reader stats lock");
    assert_eq!(stats.read_count, 1);
}

#[test]
fn zero_timestamp_scale_remains_accepted() {
    let (mut normalizer, _receiver) = live_edge_normalizer(Cursor::new(empty_clip_bytes()));

    normalizer
        .handle_tag(PositionedTag {
            tag: MatroskaSpec::TimestampScale(0),
            offset: 0,
        })
        .expect("accept timestamp scale");

    assert_eq!(normalizer.timestamp_scale_ns, 0);
}

fn cross_cluster_replay_bytes() -> Vec<u8> {
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
        .expect("write first cluster start");
    writer
        .write(&MatroskaSpec::Timestamp(0))
        .expect("write first cluster timestamp");
    writer
        .write(&MatroskaSpec::from(SimpleBlock::new_uncheked(
            &[0],
            1,
            0,
            false,
            None,
            false,
            true,
        )))
        .expect("write first frame");
    writer
        .write(&MatroskaSpec::Cluster(Master::Full(vec![
            MatroskaSpec::Timestamp(30),
            MatroskaSpec::from(SimpleBlock::new_uncheked(&[1], 1, 0, false, None, false, false)),
            MatroskaSpec::from(SimpleBlock::new_uncheked(&[1], 1, 30, false, None, false, false)),
        ])))
        .expect("write known-size second cluster");
    writer.into_inner().expect("finish cross-cluster fixture")
}
