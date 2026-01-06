#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use std::str::FromStr as _;

use devolutions_gateway::config::dto::*;
use rstest::*;
use tap::prelude::*;
use uuid::Uuid;

struct Sample {
    json_repr: &'static str,
    file_conf: ConfFile,
}

fn hub_sample() -> Sample {
    Sample {
        json_repr: r#"{
        	"Id": "123e4567-e89b-12d3-a456-426614174000",
        	"Hostname": "hostname.example.io",
        	"TlsPrivateKeyFile": "/path/to/tls-private.key",
        	"TlsCertificateFile": "/path/to/tls-certificate.pem",
        	"TlsVerifyStrict": true,
        	"ProvisionerPublicKeyFile": "/path/to/provisioner.pub.key",
            "SubProvisionerPublicKey": {
                "Id": "subkey-id",
                "Format": "Rsa",
                "Encoding": "Base64Pad",
                "Value": "subkey-value"
            },
            "DelegationPrivateKeyData": {
                "Value": "delegation-key-value"
            },
        	"Listeners": [
        		{
        			"InternalUrl": "tcp://*:8080",
        			"ExternalUrl": "tcp://*:8080"
        		},
        		{
        			"InternalUrl": "ws://*:7171",
        			"ExternalUrl": "wss://*:443"
        		}
        	],
        	"VerbosityProfile": "Tls"
        }"#,
        file_conf: ConfFile {
            id: Some(Uuid::from_str("123e4567-e89b-12d3-a456-426614174000").unwrap()),
            hostname: Some("hostname.example.io".to_owned()),
            provisioner_public_key_file: Some("/path/to/provisioner.pub.key".into()),
            provisioner_public_key_data: None,
            provisioner_private_key_file: None,
            provisioner_private_key_data: None,
            sub_provisioner_public_key: Some(SubProvisionerKeyConf {
                id: "subkey-id".to_owned(),
                data: ConfData {
                    value: "subkey-value".to_owned(),
                    format: PubKeyFormat::Pkcs1,
                    encoding: DataEncoding::Base64Pad,
                },
            }),
            delegation_private_key_file: None,
            delegation_private_key_data: Some(ConfData {
                value: "delegation-key-value".to_owned(),
                format: PrivKeyFormat::Pkcs8,
                encoding: DataEncoding::Multibase,
            }),
            tls_certificate_source: None,
            tls_certificate_file: Some("/path/to/tls-certificate.pem".into()),
            tls_private_key_file: Some("/path/to/tls-private.key".into()),
            tls_private_key_password: None,
            tls_certificate_subject_name: None,
            tls_certificate_store_location: None,
            tls_certificate_store_name: None,
            tls_verify_strict: Some(true),
            listeners: vec![
                ListenerConf {
                    internal_url: "tcp://*:8080".to_owned(),
                    external_url: "tcp://*:8080".to_owned(),
                },
                ListenerConf {
                    internal_url: "ws://*:7171".to_owned(),
                    external_url: "wss://*:443".to_owned(),
                },
            ],
            subscriber: None,
            log_file: None,
            jrl_file: None,
            plugins: None,
            recording_path: None,
            job_queue_database: None,
            traffic_audit_database: None,
            ngrok: None,
            verbosity_profile: Some(VerbosityProfile::Tls),
            web_app: None,
            ai_gateway: None,
            debug: None,
            rest: Default::default(),
        },
    }
}

fn legacy_sample() -> Sample {
    Sample {
        json_repr: r#"{
            "PrivateKeyFile": "/path/to/tls-private.key",
            "CertificateFile": "/path/to/tls-certificate.pem",
            "ProvisionerPublicKeyFile": "/path/to/provisioner.pub.key",
            "Listeners": [],
            "LogFile": "/path/to/log/file.log"
        }"#,
        file_conf: ConfFile {
            id: None,
            hostname: None,
            provisioner_public_key_file: Some("/path/to/provisioner.pub.key".into()),
            provisioner_public_key_data: None,
            provisioner_private_key_file: None,
            provisioner_private_key_data: None,
            sub_provisioner_public_key: None,
            delegation_private_key_file: None,
            delegation_private_key_data: None,
            tls_certificate_source: None,
            tls_certificate_file: Some("/path/to/tls-certificate.pem".into()),
            tls_private_key_file: Some("/path/to/tls-private.key".into()),
            tls_private_key_password: None,
            tls_certificate_subject_name: None,
            tls_certificate_store_location: None,
            tls_certificate_store_name: None,
            tls_verify_strict: None,
            listeners: vec![],
            subscriber: None,
            log_file: Some("/path/to/log/file.log".into()),
            jrl_file: None,
            plugins: None,
            recording_path: None,
            job_queue_database: None,
            traffic_audit_database: None,
            ngrok: None,
            verbosity_profile: None,
            web_app: None,
            ai_gateway: None,
            debug: None,
            rest: Default::default(),
        },
    }
}

fn system_store_sample() -> Sample {
    Sample {
        json_repr: r#"{
            "TlsCertificateSource": "System",
            "TlsCertificateSubjectName": "localhost",
            "TlsCertificateStoreLocation": "LocalMachine",
            "TlsCertificateStoreName": "My"
        }"#,
        file_conf: ConfFile {
            id: None,
            hostname: None,
            provisioner_public_key_file: None,
            provisioner_public_key_data: None,
            provisioner_private_key_file: None,
            provisioner_private_key_data: None,
            sub_provisioner_public_key: None,
            delegation_private_key_file: None,
            delegation_private_key_data: None,
            tls_certificate_source: Some(CertSource::System),
            tls_certificate_file: None,
            tls_private_key_file: None,
            tls_private_key_password: None,
            tls_certificate_subject_name: Some("localhost".to_owned()),
            tls_certificate_store_location: Some(CertStoreLocation::LocalMachine),
            tls_certificate_store_name: Some("My".to_owned()),
            tls_verify_strict: None,
            listeners: vec![],
            subscriber: None,
            log_file: None,
            jrl_file: None,
            plugins: None,
            recording_path: None,
            job_queue_database: None,
            traffic_audit_database: None,
            ngrok: None,
            verbosity_profile: None,
            web_app: None,
            ai_gateway: None,
            debug: None,
            rest: Default::default(),
        },
    }
}

fn standalone_custom_auth_sample() -> Sample {
    Sample {
        json_repr: r#"{
            "Id": "aa0b2a02-ba9d-4e87-b707-03c6391b86fb",
            "Hostname": "hostname.example.io",
            "ProvisionerPublicKeyFile": "provisioner.pem",
            "ProvisionerPrivateKeyFile": "provisioner.key",
            "Listeners": [
                {
                    "InternalUrl": "tcp://*:8080",
                    "ExternalUrl": "tcp://*:8080"
                },
                {
                    "InternalUrl": "http://*:7171",
                    "ExternalUrl": "https://*:7171"
                }
            ],
            "WebApp": {
                "Enabled": true,
                "Authentication": "Custom",
                "AppTokenMaximumLifetime": 28800,
                "LoginLimitRate": 10
            }
        }"#,
        file_conf: ConfFile {
            id: Some(Uuid::from_str("aa0b2a02-ba9d-4e87-b707-03c6391b86fb").unwrap()),
            hostname: Some("hostname.example.io".to_owned()),
            provisioner_public_key_file: Some("provisioner.pem".into()),
            provisioner_public_key_data: None,
            provisioner_private_key_file: Some("provisioner.key".into()),
            provisioner_private_key_data: None,
            sub_provisioner_public_key: None,
            delegation_private_key_file: None,
            delegation_private_key_data: None,
            tls_certificate_source: None,
            tls_certificate_file: None,
            tls_private_key_file: None,
            tls_private_key_password: None,
            tls_certificate_subject_name: None,
            tls_certificate_store_location: None,
            tls_certificate_store_name: None,
            tls_verify_strict: None,
            listeners: vec![
                ListenerConf {
                    internal_url: "tcp://*:8080".to_owned(),
                    external_url: "tcp://*:8080".to_owned(),
                },
                ListenerConf {
                    internal_url: "http://*:7171".to_owned(),
                    external_url: "https://*:7171".to_owned(),
                },
            ],
            subscriber: None,
            log_file: None,
            jrl_file: None,
            plugins: None,
            recording_path: None,
            job_queue_database: None,
            traffic_audit_database: None,
            ngrok: None,
            verbosity_profile: None,
            web_app: Some(WebAppConf {
                enabled: true,
                authentication: WebAppAuth::Custom,
                app_token_maximum_lifetime: Some(28800),
                login_limit_rate: Some(10),
                users_file: None,
                static_root_path: None,
            }),
            ai_gateway: None,
            debug: None,
            rest: Default::default(),
        },
    }
}

fn standalone_no_auth_sample() -> Sample {
    Sample {
        json_repr: r#"{
            "Id": "aa0b2a02-ba9d-4e87-b707-03c6391b86fb",
            "Hostname": "hostname.example.io",
            "ProvisionerPublicKeyFile": "provisioner.pem",
            "ProvisionerPrivateKeyFile": "provisioner.key",
            "Listeners": [
                {
                    "InternalUrl": "tcp://*:8080",
                    "ExternalUrl": "tcp://*:8080"
                },
                {
                    "InternalUrl": "http://*:7171",
                    "ExternalUrl": "https://*:7171"
                }
            ],
            "WebApp": {
                "Enabled": true,
                "Authentication": "None",
                "UsersFile": "/path/to/users.txt",
                "StaticRootPath": "/path/to/webapp/static/root"
            }
        }"#,
        file_conf: ConfFile {
            id: Some(Uuid::from_str("aa0b2a02-ba9d-4e87-b707-03c6391b86fb").unwrap()),
            hostname: Some("hostname.example.io".to_owned()),
            provisioner_public_key_file: Some("provisioner.pem".into()),
            provisioner_public_key_data: None,
            provisioner_private_key_file: Some("provisioner.key".into()),
            provisioner_private_key_data: None,
            sub_provisioner_public_key: None,
            delegation_private_key_file: None,
            delegation_private_key_data: None,
            tls_certificate_source: None,
            tls_certificate_file: None,
            tls_private_key_file: None,
            tls_private_key_password: None,
            tls_certificate_subject_name: None,
            tls_certificate_store_location: None,
            tls_certificate_store_name: None,
            tls_verify_strict: None,
            listeners: vec![
                ListenerConf {
                    internal_url: "tcp://*:8080".to_owned(),
                    external_url: "tcp://*:8080".to_owned(),
                },
                ListenerConf {
                    internal_url: "http://*:7171".to_owned(),
                    external_url: "https://*:7171".to_owned(),
                },
            ],
            subscriber: None,
            log_file: None,
            jrl_file: None,
            plugins: None,
            recording_path: None,
            job_queue_database: None,
            traffic_audit_database: None,
            ngrok: None,
            verbosity_profile: None,
            web_app: Some(WebAppConf {
                enabled: true,
                authentication: WebAppAuth::None,
                app_token_maximum_lifetime: None,
                login_limit_rate: None,
                users_file: Some("/path/to/users.txt".into()),
                static_root_path: Some("/path/to/webapp/static/root".into()),
            }),
            ai_gateway: None,
            debug: None,
            rest: Default::default(),
        },
    }
}

#[rstest]
#[case(hub_sample())]
#[case(legacy_sample())]
#[case(system_store_sample())]
#[case(standalone_custom_auth_sample())]
#[case(standalone_no_auth_sample())]
fn sample_parsing(#[case] sample: Sample) {
    let from_json = serde_json::from_str::<ConfFile>(sample.json_repr)
        .unwrap()
        .pipe_ref(serde_json::to_value)
        .unwrap();

    let from_struct = serde_json::to_value(&sample.file_conf).unwrap();

    assert_eq!(from_json, from_struct);
}
