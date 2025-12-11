#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_engine_initialization() {
        let config = crate::config::MLConfig {
            model_path: "models/test_model.onnx".to_string(),
            enabled: true,
        };
        let mut ml_engine = crate::ml::MLInferenceEngine::new(&config);
        assert!(ml_engine.initialize().is_ok());
    }

    #[test]
    fn test_behavior_monitor_creation() {
        let config = crate::config::BehaviorConfig {
            watch_paths: vec![".".to_string()],
            enabled: true,
        };
        let behavior_monitor = crate::behavior::BehaviorMonitor::new(&config);
        assert!(true); // Just testing creation
    }

    #[test]
    fn test_security_manager_creation() {
        let config = crate::config::SecurityConfig {
            server_url: "https://api.aegisai.local".to_string(),
            api_key: "test-key".to_string(),
            verify_updates: true,
        };
        let security_manager = crate::security::SecurityManager::new(&config);
        assert!(true); // Just testing creation
    }
}