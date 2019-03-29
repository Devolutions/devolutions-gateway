use crate::{
    encryption::rc4::Rc4,
    ntlm::{
        messages::{computations::*, CLIENT_SEAL_MAGIC, CLIENT_SIGN_MAGIC, SERVER_SEAL_MAGIC, SERVER_SIGN_MAGIC},
        Mic, Ntlm, NtlmState, MESSAGE_INTEGRITY_CHECK_SIZE,
    },
    sspi::{self, SspiError, SspiErrorType},
};

pub fn complete_authenticate(mut context: &mut Ntlm) -> sspi::Result<()> {
    check_state(context.state)?;

    let negotiate_message = context
        .negotiate_message
        .as_ref()
        .expect("negotiate message must be set on negotiate phase");
    let challenge_message = context
        .challenge_message
        .as_ref()
        .expect("challenge message must be set on challenge phase");
    let authenticate_message = context
        .authenticate_message
        .as_ref()
        .expect("authenticate message must be set on authenticate phase");

    let session_key = authenticate_message.session_key.as_ref();
    context.send_signing_key = generate_signing_key(session_key, SERVER_SIGN_MAGIC);
    context.recv_signing_key = generate_signing_key(session_key, CLIENT_SIGN_MAGIC);
    context.send_sealing_key = Some(Rc4::new(&generate_signing_key(session_key, SERVER_SEAL_MAGIC)));
    context.recv_sealing_key = Some(Rc4::new(&generate_signing_key(session_key, CLIENT_SEAL_MAGIC)));

    check_mic_correctness(
        negotiate_message.message.as_ref(),
        challenge_message.message.as_ref(),
        authenticate_message.message.as_ref(),
        &authenticate_message.mic,
        authenticate_message.session_key.as_ref(),
    )?;

    context.state = NtlmState::Final;

    Ok(())
}

fn check_state(state: NtlmState) -> sspi::Result<()> {
    if state != NtlmState::Completion {
        Err(SspiError::new(
            SspiErrorType::OutOfSequence,
            String::from("Complete authenticate was fired but the state is not a Completion"),
        ))
    } else {
        Ok(())
    }
}

fn check_mic_correctness(
    negotiate_message: &[u8],
    challenge_message: &[u8],
    authenticate_message: &[u8],
    mic: &Option<Mic>,
    exported_session_key: &[u8],
) -> sspi::Result<()> {
    if mic.is_some() {
        // Client calculates the MIC with the authenticate message
        // without the MIC ([0x00;16] instead of data),
        // so for check correctness of the MIC,
        // we need empty the MIC part of auth. message and then will come back the MIC.
        let mic = mic.as_ref().unwrap();
        let mut authenticate_message = authenticate_message.to_vec();
        authenticate_message[mic.offset as usize..mic.offset as usize + MESSAGE_INTEGRITY_CHECK_SIZE]
            .clone_from_slice(&[0x00; MESSAGE_INTEGRITY_CHECK_SIZE]);
        let calculated_mic = compute_message_integrity_check(
            negotiate_message,
            challenge_message,
            authenticate_message.as_ref(),
            exported_session_key,
        )?;

        if mic.value != calculated_mic {
            return Err(SspiError::new(
                SspiErrorType::MessageAltered,
                String::from("Message Integrity Check (MIC) verification failed!"),
            ));
        }
    }

    Ok(())
}
