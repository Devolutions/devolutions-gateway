mod config;
mod tunnel;

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(name = "devolutions-gateway-agent")]
#[command(about = "WireGuard agent for Devolutions Gateway", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the agent
    Run {
        /// Path to configuration file
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
        /// Additional subnets to advertise to Gateway (repeatable)
        #[arg(long = "advertise-subnet", value_name = "CIDR")]
        advertise_subnets: Vec<String>,
    },

    /// Generate a sample configuration file
    GenConfig {
        /// Output path for sample config
        #[arg(short, long, value_name = "FILE", default_value = "agent-config.toml")]
        output: PathBuf,
    },

    /// Generate a new WireGuard keypair
    Keygen,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            config,
            advertise_subnets,
        } => {
            // Initialize tracing
            init_tracing();

            info!("Starting Devolutions Gateway Agent");
            info!("Loading configuration from: {}", config.display());

            // Load configuration
            let mut agent_config = config::AgentConfig::from_file(&config)?;
            merge_advertise_subnets(&mut agent_config, advertise_subnets);
            let runtime_config = agent_config.into_runtime()?;

            info!(
                agent_id = %runtime_config.agent_id,
                name = %runtime_config.name,
                gateway = %runtime_config.gateway_endpoint,
                "Agent configuration loaded"
            );

            // Create tunnel manager
            let tunnel_manager = tunnel::TunnelManager::new(&runtime_config)
                .await
                .context("Failed to create tunnel manager")?;

            // Run tunnel
            if let Err(e) = tunnel_manager.run().await {
                error!(error = format!("{:#}", e), "Tunnel manager failed");
                return Err(e);
            }

            Ok(())
        }

        Commands::GenConfig { output } => {
            let sample = config::generate_sample_config();
            std::fs::write(&output, sample)
                .with_context(|| format!("Failed to write config to {}", output.display()))?;

            println!("Sample configuration written to: {}", output.display());
            println!("\nNext steps:");
            println!("1. Generate keypair: devolutions-gateway-agent keygen");
            println!("2. Edit {} with your settings", output.display());
            println!(
                "3. Run agent: devolutions-gateway-agent run --config {}",
                output.display()
            );

            Ok(())
        }

        Commands::Keygen => {
            use wireguard_tunnel::StaticSecret;

            // Generate new keypair
            let private_key = StaticSecret::random_from_rng(rand::thread_rng());
            let public_key = wireguard_tunnel::PublicKey::from(&private_key);

            // Encode to base64
            let private_b64 = base64::engine::general_purpose::STANDARD.encode(private_key.as_bytes());
            let public_b64 = base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes());

            println!("Generated WireGuard keypair:\n");
            println!("Private key (keep secret!):");
            println!("  {}", private_b64);
            println!("\nPublic key (share with gateway):");
            println!("  {}", public_b64);
            println!("\nAdd the private key to your agent config file.");
            println!("Add the public key to the gateway config for this agent.");

            Ok(())
        }
    }
}

fn merge_advertise_subnets(agent_config: &mut config::AgentConfig, cli_subnets: Vec<String>) {
    let mut merged = BTreeSet::new();
    merged.extend(agent_config.advertise_subnets.iter().cloned());
    merged.extend(cli_subnets);
    agent_config.advertise_subnets = merged.into_iter().collect();
}

/// Initialize tracing subscriber
fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,devolutions_gateway_agent=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_advertise_subnets_unions_config_and_cli() {
        let mut agent_config = config::AgentConfig {
            agent_id: uuid::Uuid::new_v4(),
            name: "test-agent".to_owned(),
            gateway_endpoint: "127.0.0.1:51820".to_owned(),
            private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            gateway_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            assigned_ip: "10.10.0.2".parse().expect("valid IPv4"),
            gateway_ip: "10.10.0.1".parse().expect("valid IPv4"),
            advertise_subnets: vec!["192.168.100.0/24".to_owned()],
            keepalive_interval: Some(25),
        };

        merge_advertise_subnets(
            &mut agent_config,
            vec!["10.20.0.0/16".to_owned(), "192.168.100.0/24".to_owned()],
        );

        assert_eq!(
            agent_config.advertise_subnets,
            vec!["10.20.0.0/16".to_owned(), "192.168.100.0/24".to_owned()]
        );
    }
}
