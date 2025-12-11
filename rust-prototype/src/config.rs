// AegisAI Configuration Module
// ============================

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub scanner: ScannerConfig,
    pub behavior: BehaviorConfig,
    pub ml: MLConfig,
    pub decision: DecisionConfig,
    pub update: UpdateConfig,
    pub security: SecurityConfig,
    pub privacy: PrivacyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub signature_db_path: String,
    pub max_file_size: u64,
    pub excluded_paths: Vec<String>,
    pub excluded_extensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorConfig {
    pub monitor_processes: bool,
    pub monitor_network: bool,
    pub monitor_file_access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLConfig {
    pub model_path: String,
    pub enable_local_inference: bool,
    pub enable_cloud_inference: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionConfig {
    pub threshold_suspicious: f32,
    pub threshold_malicious: f32,
    pub enable_quarantine: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    pub server_url: String,
    pub check_interval: u64,
    pub enable_delta_updates: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub server_url: String,
    pub server_certificate: String,
    pub client_certificate: String,
    pub client_private_key: String,
    pub enable_mtls: bool,
    pub rate_limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    pub enable_telemetry: bool,
    pub telemetry_consent: bool,
    pub anonymize_data: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            scanner: ScannerConfig {
                signature_db_path: "signatures/signatures.db".to_string(),
                max_file_size: 100 * 1024 * 1024, // 100MB
                excluded_paths: vec![
                    "/tmp".to_string(),
                    "/var/tmp".to_string(),
                    "/proc".to_string(),
                ],
                excluded_extensions: vec![
                    ".tmp".to_string(),
                    ".log".to_string(),
                ],
            },
            behavior: BehaviorConfig {
                monitor_processes: true,
                monitor_network: true,
                monitor_file_access: true,
            },
            ml: MLConfig {
                model_path: "models/test_model.onnx".to_string(),
                enable_local_inference: true,
                enable_cloud_inference: true,
            },
            decision: DecisionConfig {
                threshold_suspicious: 0.3,
                threshold_malicious: 0.7,
                enable_quarantine: true,
            },
            update: UpdateConfig {
                server_url: "https://updates.aegisai.local".to_string(),
                check_interval: 3600, // 1 hour
                enable_delta_updates: true,
            },
            security: SecurityConfig {
                server_url: "https://api.aegisai.local".to_string(),
                server_certificate: "certs/server.crt".to_string(),
                client_certificate: "certs/client.crt".to_string(),
                client_private_key: "certs/client.key".to_string(),
                enable_mtls: true,
                rate_limit: 100,
            },
            privacy: PrivacyConfig {
                enable_telemetry: true,
                telemetry_consent: false,
                anonymize_data: true,
            },
        }
    }
}

pub fn load_config() -> Result<AgentConfig, Box<dyn std::error::Error>> {
    // In a real implementation, this would load configuration from a file
    // For this prototype, we'll return the default configuration
    Ok(AgentConfig::default())
}