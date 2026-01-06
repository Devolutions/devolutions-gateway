use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::Context as _;
use devolutions_gateway_task::ChildTask;
use parking_lot::{Condvar, Mutex};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::interceptor::{Inspector, PeerSide};
use crate::plugin_manager::{PLUGIN_MANAGER, PacketsParser, Recorder};

#[derive(Debug)]
enum RecordingState {
    Update,
    Finish,
}

pub struct PluginRecordingInspector {
    side: PeerSide,
    sender: mpsc::UnboundedSender<(PeerSide, Vec<u8>)>,
}

impl Inspector for PluginRecordingInspector {
    fn inspect_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.sender
            .send((self.side, bytes.to_vec()))
            .context("plugin Recording inspector task is terminated")?;
        Ok(())
    }
}

pub struct InitResult {
    pub client_inspector: PluginRecordingInspector,
    pub server_inspector: PluginRecordingInspector,
    pub filename_pattern: String,
    pub recording_dir: Option<PathBuf>,
}

impl PluginRecordingInspector {
    pub fn init(association_id: Uuid, candidate_id: Uuid, recording_directory: &str) -> anyhow::Result<InitResult> {
        debug!("Initialize Plugin Recording Interceptor");

        let recorder = PLUGIN_MANAGER
            .lock()
            .get_recording_plugin()
            .context("recording plugin missing")?;

        let packet_parser = PLUGIN_MANAGER
            .lock()
            .get_parsing_packets_plugin()
            .context("packet parser plugin missing")?;

        let filename = format!("{association_id}-to-{candidate_id}");

        recorder.set_filename(&filename);

        recorder.set_directory(recording_directory);

        let (sender, receiver) = mpsc::unbounded_channel();

        let condition_timeout = Arc::new((Mutex::new(RecordingState::Update), Condvar::new()));

        let recording_dir = match recorder.get_filepath() {
            Ok(path_buf) => {
                debug!("the path is {:?}", path_buf.to_str());
                Some(path_buf)
            }
            Err(e) => {
                error!("Failed to get video path: {}", e);
                None
            }
        };

        let recorder = Arc::new(Mutex::new(recorder));

        // FIXME: use a tokio task instead
        let handle = thread::spawn({
            let recorder = Arc::clone(&recorder);
            let condition_timeout = Arc::clone(&condition_timeout);
            move || timeout_task(recorder, condition_timeout)
        });

        ChildTask::spawn(inspector_task(
            receiver,
            handle,
            packet_parser,
            recorder,
            condition_timeout,
        ))
        .detach();

        Ok(InitResult {
            client_inspector: Self {
                side: PeerSide::Client,
                sender: sender.clone(),
            },
            server_inspector: Self {
                side: PeerSide::Server,
                sender,
            },
            filename_pattern: filename,
            recording_dir,
        })
    }
}

fn timeout_task(recorder: Arc<Mutex<Recorder>>, condition_timeout: Arc<(Mutex<RecordingState>, Condvar)>) {
    loop {
        let timeout = recorder.lock().get_timeout();
        let (state, cond_var) = condition_timeout.as_ref();
        let mut state_guard = state.lock();
        let timeout_result = cond_var.wait_for(&mut state_guard, Duration::from_millis(u64::from(timeout)));
        match *state_guard {
            RecordingState::Update if timeout_result.timed_out() => recorder.lock().timeout(),
            RecordingState::Update => {}
            RecordingState::Finish => break,
        }
    }
}

async fn inspector_task(
    mut receiver: mpsc::UnboundedReceiver<(PeerSide, Vec<u8>)>,
    handle: thread::JoinHandle<()>,
    packet_parser: PacketsParser,
    recorder: Arc<Mutex<Recorder>>,
    condition_timeout: Arc<(Mutex<RecordingState>, Condvar)>,
) {
    while let Some((side, bytes)) = receiver.recv().await {
        debug!("New packet intercepted. Packet size = {}", bytes.len());

        match side {
            PeerSide::Client => {}
            PeerSide::Server => {
                let (state, cond_var) = condition_timeout.as_ref();
                let mut state_guard = state.lock();
                *state_guard = RecordingState::Update;
                cond_var.notify_one();
            }
        }

        let is_from_server = matches!(side, PeerSide::Server);

        let (status, message_id) = packet_parser.parse_message(&bytes, bytes.len(), is_from_server);
        debug!(
            "Returned from parse message with status: {} and message_id: {}",
            status, message_id
        );

        if packet_parser.is_message_constructed(is_from_server) && message_id == PacketsParser::NOW_UPDATE_MSG_ID {
            let size = packet_parser.get_size();
            let image_data = packet_parser.get_image_data();

            let recorder = recorder.lock();
            recorder.set_size(size.width, size.height);
            recorder.update_recording(image_data);
        }
    }

    {
        let (state, cond_var) = condition_timeout.as_ref();
        let mut state_guard = state.lock();
        *state_guard = RecordingState::Finish;
        cond_var.notify_one();
    }

    if let Err(e) = handle.join() {
        error!("Failed to join the thread: {:?}", e);
    }
}
