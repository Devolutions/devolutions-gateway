use crate::rdp::sequence_future::post_mcs::{IndicationData, SequenceState};
use ironrdp::rdp::server_license::{
    ClientNewLicenseRequest, ClientPlatformChallengeResponse, InitialMessageType, InitialServerLicenseMessage,
    LicenseEncryptionData, ServerLicenseError, ServerPlatformChallenge, ServerUpgradeLicense, PREMASTER_SECRET_SIZE,
    RANDOM_NUMBER_SIZE,
};
use ironrdp::rdp::RdpError;
use ironrdp::PduParsing;
use ring::rand::SecureRandom;
use std::io;

pub struct LicenseCredentials {
    pub username: String,
    pub hostname: String,
}

pub struct LicenseData {
    pub encryption_data: Option<LicenseEncryptionData>,
    pub credentials: LicenseCredentials,
}

pub fn process_license_request(
    pdu: &[u8],
    credentials: &LicenseCredentials,
) -> io::Result<(SequenceState, Vec<u8>, IndicationData)> {
    let initial_message = InitialServerLicenseMessage::from_buffer(pdu).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("An error occurred during reading Initial Server License Message: {err:?}"),
        )
    })?;

    debug!("Received Initial License Message PDU");
    trace!("{:?}", initial_message);

    match initial_message.message_type {
        InitialMessageType::LicenseRequest(license_request) => {
            let mut client_random = vec![0u8; RANDOM_NUMBER_SIZE];

            let rand = ring::rand::SystemRandom::new();
            rand.fill(&mut client_random)
                .map_err(|err| RdpError::IOError(io::Error::new(io::ErrorKind::InvalidData, format!("{err}"))))?;

            let mut premaster_secret = vec![0u8; PREMASTER_SECRET_SIZE];
            rand.fill(&mut premaster_secret)
                .map_err(|err| RdpError::IOError(io::Error::new(io::ErrorKind::InvalidData, format!("{err}"))))?;

            let (new_license_request, encryption_data) = ClientNewLicenseRequest::from_server_license_request(
                &license_request,
                client_random.as_slice(),
                premaster_secret.as_slice(),
                &credentials.username,
                &credentials.hostname,
            )
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unable to generate Client New License Request from Server License Request: {err}"),
                )
            })?;

            let mut new_license_request_buffer = Vec::with_capacity(new_license_request.buffer_length());
            new_license_request
                .to_buffer(&mut new_license_request_buffer)
                .map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Received an error during writing Client New License Request: {err}"),
                    )
                })?;

            Ok((
                SequenceState::ServerChallenge,
                new_license_request_buffer,
                IndicationData {
                    originator_id: None,
                    encryption_data: Some(encryption_data),
                },
            ))
        }
        InitialMessageType::StatusValidClient(_) => {
            info!("The server has not initiated license exchange");

            let valid_client = InitialServerLicenseMessage::new_status_valid_client_message();

            let mut valid_client_buffer = Vec::with_capacity(valid_client.buffer_length());
            valid_client
                .to_buffer(&mut valid_client_buffer)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("{err}")))?;

            Ok((
                SequenceState::ServerDemandActive,
                valid_client_buffer,
                IndicationData {
                    originator_id: None,
                    encryption_data: None,
                },
            ))
        }
    }
}

pub fn process_challenge(
    pdu: &[u8],
    encryption_data: Option<LicenseEncryptionData>,
    credentials: &LicenseCredentials,
) -> io::Result<(SequenceState, Vec<u8>, IndicationData)> {
    let challenge = match ServerPlatformChallenge::from_buffer(pdu) {
        Err(ServerLicenseError::UnexpectedValidClientError(_)) => {
            warn!("The server has returned STATUS_VALID_CLIENT unexpectedly");

            let valid_client = InitialServerLicenseMessage::new_status_valid_client_message();

            let mut valid_client_buffer = Vec::with_capacity(valid_client.buffer_length());
            valid_client.to_buffer(&mut valid_client_buffer).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Received an error during writing Status Valid Client message: {err}"),
                )
            })?;

            return Ok((
                SequenceState::ServerDemandActive,
                valid_client_buffer,
                IndicationData {
                    originator_id: None,
                    encryption_data: None,
                },
            ));
        }
        Err(error) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("An error occurred during reading Initial Server License Message: {error:?}"),
            ));
        }
        Ok(challenge) => challenge,
    };

    debug!("Received Server Platform Challenge PDU");
    trace!("{:?}", challenge);

    let encryption_data = encryption_data.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "License encryption data was missing during creation of Client Platform Challenge Response",
        )
    })?;

    let challenge_response = ClientPlatformChallengeResponse::from_server_platform_challenge(
        &challenge,
        &credentials.hostname,
        &encryption_data,
    )
    .map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unable to generate Client Platform Challenge Response {err}"),
        )
    })?;

    debug!("Successfully generated Client Platform Challenge Response");
    trace!("{:?}", challenge_response);

    let mut challenge_response_buffer = Vec::with_capacity(challenge_response.buffer_length());
    challenge_response
        .to_buffer(&mut challenge_response_buffer)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Received an error during writing Client Platform Challenge Response: {err}"),
            )
        })?;

    Ok((
        SequenceState::ServerUpgradeLicense,
        challenge_response_buffer,
        IndicationData {
            originator_id: None,
            encryption_data: Some(encryption_data),
        },
    ))
}

pub fn process_upgrade_license(
    pdu: &[u8],
    encryption_data: Option<LicenseEncryptionData>,
) -> io::Result<(SequenceState, Vec<u8>, IndicationData)> {
    let upgrade_license = match ServerUpgradeLicense::from_buffer(pdu) {
        Err(ServerLicenseError::UnexpectedValidClientError(_)) => {
            warn!("The server has returned STATUS_VALID_CLIENT unexpectedly");

            let valid_client = InitialServerLicenseMessage::new_status_valid_client_message();

            let mut valid_client_buffer = Vec::with_capacity(valid_client.buffer_length());
            valid_client.to_buffer(&mut valid_client_buffer).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Received an error during writing Status Valid Client message: {err}"),
                )
            })?;

            return Ok((
                SequenceState::ServerDemandActive,
                valid_client_buffer,
                IndicationData {
                    originator_id: None,
                    encryption_data: None,
                },
            ));
        }
        Err(error) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("An error occurred during reading Initial Server License Message: {error:?}"),
            ));
        }
        Ok(challenge) => challenge,
    };

    let encryption_data = encryption_data.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "License encryption data was missing during creation of Client Platform Challenge Response",
        )
    })?;

    upgrade_license.verify_server_license(&encryption_data).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("License verification failed: {err:?}"),
        )
    })?;

    debug!("Successfully verified the license");

    let valid_client = InitialServerLicenseMessage::new_status_valid_client_message();

    let mut valid_client_buffer = Vec::with_capacity(valid_client.buffer_length());
    valid_client.to_buffer(&mut valid_client_buffer).map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Received an error during writing Status Valid Client message: {err}"),
        )
    })?;

    Ok((
        SequenceState::ServerDemandActive,
        valid_client_buffer,
        IndicationData {
            originator_id: None,
            encryption_data: None,
        },
    ))
}
