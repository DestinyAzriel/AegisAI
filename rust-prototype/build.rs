// AegisAI Build Script
// ====================

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Create directories needed for the agent
    let out_dir = env::var("OUT_DIR").unwrap();
    let build_dir = Path::new(&out_dir).join("aegisai");
    
    // Create models directory
    let models_dir = build_dir.join("models");
    fs::create_dir_all(&models_dir).expect("Failed to create models directory");
    
    // Create configs directory
    let configs_dir = build_dir.join("configs");
    fs::create_dir_all(&configs_dir).expect("Failed to create configs directory");
    
    // Create logs directory
    let logs_dir = build_dir.join("logs");
    fs::create_dir_all(&logs_dir).expect("Failed to create logs directory");
    
    // Create quarantine directory
    let quarantine_dir = build_dir.join("quarantine");
    fs::create_dir_all(&quarantine_dir).expect("Failed to create quarantine directory");
    
    println!("cargo:rerun-if-changed=build.rs");
    println!("Build directories created successfully");
}