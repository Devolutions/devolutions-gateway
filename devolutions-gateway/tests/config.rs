use devolutions_gateway::config::{dto::*, DataEncoding, PrivKeyFormat, PubKeyFormat};
use rstest::*;
use std::str::FromStr as _;
use tap::prelude::*;
use uuid::Uuid;

struct Sample {
    json_repr: &'static str,
    file_conf: ConfFile,
}

fn sample_1() -> Sample {
    Sample {
        json_repr: r#"{
        	"Id": "123e4567-e89b-12d3-a456-426614174000",
        	"Hostname": "hostname.example.io",
        	"TlsPrivateKeyFile": "/path/to/tls-private.key",
        	"TlsCertificateFile": "/path/to/tls-certificate.pem",
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
        	"LogDirective": "info,devolutions_gateway=trace,devolutions_gateway::log=debug"
        }"#,
        file_conf: ConfFile {
            id: Some(Uuid::from_str("123e4567-e89b-12d3-a456-426614174000").unwrap()),
            hostname: Some("hostname.example.io".to_owned()),
            provisioner_public_key: Some(ConfFileOrData::Path {
                file: "/path/to/provisioner.pub.key".into(),
            }),
            sub_provisioner_public_key: Some(SubProvisionerKeyConf {
                id: "subkey-id".to_owned(),
                inner: ConfFileOrData::Flattened(ConfData {
                    value: "subkey-value".to_owned(),
                    format: PubKeyFormat::Rsa,
                    encoding: DataEncoding::Base64Pad,
                }),
            }),
            delegation_private_key: Some(ConfFileOrData::Inlined {
                data: ConfData {
                    value: "delegation-key-value".to_owned(),
                    format: PrivKeyFormat::Pkcs8,
                    encoding: DataEncoding::Multibase,
                },
            }),
            tls: Some(TlsConf {
                tls_certificate: ConfFileOrData::Path {
                    file: "/path/to/tls-certificate.pem".into(),
                },
                tls_private_key: ConfFileOrData::Path {
                    file: "/path/to/tls-private.key".into(),
                },
            }),
            listeners: vec![
                ListenerConf {
                    internal_url: "tcp://*:8080".try_into().unwrap(),
                    external_url: "tcp://*:8080".try_into().unwrap(),
                },
                ListenerConf {
                    internal_url: "ws://*:7171".try_into().unwrap(),
                    external_url: "wss://*:443".try_into().unwrap(),
                },
            ],
            log_file: None,
            jrl_file: None,
            log_directive: Some("info,devolutions_gateway=trace,devolutions_gateway::log=debug".to_owned()),
            plugins: None,
            recording_path: None,
            capture_path: None,
            sogar: None,
            debug: None,
        },
    }
}

fn sample_2() -> Sample {
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
            provisioner_public_key: Some(ConfFileOrData::Path {
                file: "/path/to/provisioner.pub.key".into(),
            }),
            sub_provisioner_public_key: None,
            delegation_private_key: None,
            tls: Some(TlsConf {
                tls_certificate: ConfFileOrData::Path {
                    file: "/path/to/tls-certificate.pem".into(),
                },
                tls_private_key: ConfFileOrData::Path {
                    file: "/path/to/tls-private.key".into(),
                },
            }),
            listeners: vec![],
            log_file: Some("/path/to/log/file.log".into()),
            jrl_file: None,
            log_directive: None,
            plugins: None,
            recording_path: None,
            capture_path: None,
            sogar: None,
            debug: None,
        },
    }
}

#[rstest]
#[case(sample_1())]
#[case(sample_2())]
fn sample_parsing(#[case] sample: Sample) {
    let from_json = serde_json::from_str::<ConfFile>(sample.json_repr)
        .unwrap()
        .pipe_ref(serde_json::to_value)
        .unwrap();

    let from_struct = serde_json::to_value(&sample.file_conf).unwrap();

    assert_eq!(from_json, from_struct);
}
