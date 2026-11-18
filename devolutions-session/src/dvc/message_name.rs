use now_proto_pdu::{
    NowChannelMessage, NowExecMessage, NowMessage, NowRdmMessage, NowSessionMessage, NowSystemMessage,
};

/// Returns the NOW-PROTO name of a message, for logging without the message payload.
pub fn now_message_name(message: &NowMessage<'_>) -> &'static str {
    match message {
        NowMessage::Channel(msg) => match msg {
            NowChannelMessage::Capset(_) => "NOW_CHANNEL_CAPSET_MSG",
            NowChannelMessage::Heartbeat(_) => "NOW_CHANNEL_HEARTBEAT_MSG",
            NowChannelMessage::Close(_) => "NOW_CHANNEL_CLOSE_MSG",
        },
        NowMessage::System(msg) => match msg {
            NowSystemMessage::Shutdown(_) => "NOW_SYSTEM_SHUTDOWN_MSG",
        },
        NowMessage::Session(msg) => match msg {
            NowSessionMessage::Lock(_) => "NOW_SESSION_LOCK_MSG",
            NowSessionMessage::Logoff(_) => "NOW_SESSION_LOGOFF_MSG",
            NowSessionMessage::MsgBoxReq(_) => "NOW_SESSION_MSGBOX_REQ_MSG",
            NowSessionMessage::MsgBoxRsp(_) => "NOW_SESSION_MSGBOX_RSP_MSG",
            NowSessionMessage::SetKbdLayout(_) => "NOW_SESSION_SET_KBD_LAYOUT_MSG",
            NowSessionMessage::WindowRecStart(_) => "NOW_SESSION_WINDOW_REC_START_MSG",
            NowSessionMessage::WindowRecStop(_) => "NOW_SESSION_WINDOW_REC_STOP_MSG",
            NowSessionMessage::WindowRecEvent(_) => "NOW_SESSION_WINDOW_REC_EVENT_MSG",
        },
        NowMessage::Exec(msg) => match msg {
            NowExecMessage::Abort(_) => "NOW_EXEC_ABORT_MSG",
            NowExecMessage::CancelReq(_) => "NOW_EXEC_CANCEL_REQ_MSG",
            NowExecMessage::CancelRsp(_) => "NOW_EXEC_CANCEL_RSP_MSG",
            NowExecMessage::Result(_) => "NOW_EXEC_RESULT_MSG",
            NowExecMessage::Data(_) => "NOW_EXEC_DATA_MSG",
            NowExecMessage::Started(_) => "NOW_EXEC_STARTED_MSG",
            NowExecMessage::Run(_) => "NOW_EXEC_RUN_MSG",
            NowExecMessage::Process(_) => "NOW_EXEC_PROCESS_MSG",
            NowExecMessage::Shell(_) => "NOW_EXEC_SHELL_MSG",
            NowExecMessage::Batch(_) => "NOW_EXEC_BATCH_MSG",
            NowExecMessage::WinPs(_) => "NOW_EXEC_WINPS_MSG",
            NowExecMessage::Pwsh(_) => "NOW_EXEC_PWSH_MSG",
        },
        NowMessage::Rdm(msg) => match msg {
            NowRdmMessage::Capabilities(_) => "NOW_RDM_CAPABILITIES_MSG",
            NowRdmMessage::AppStart(_) => "NOW_RDM_APP_START_MSG",
            NowRdmMessage::AppAction(_) => "NOW_RDM_APP_ACTION_MSG",
            NowRdmMessage::AppNotify(_) => "NOW_RDM_APP_NOTIFY_MSG",
            NowRdmMessage::SessionStart(_) => "NOW_RDM_SESSION_START_MSG",
            NowRdmMessage::SessionAction(_) => "NOW_RDM_SESSION_ACTION_MSG",
            NowRdmMessage::SessionNotify(_) => "NOW_RDM_SESSION_NOTIFY_MSG",
        },
    }
}
