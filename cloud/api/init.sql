-- AegisAI Database Initialization Script
-- This script is executed when the PostgreSQL container starts

-- Create the aegisai user
CREATE USER aegisai WITH PASSWORD 'aegisai_password';

-- Create the aegisai database
CREATE DATABASE aegisai WITH OWNER aegisai;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE aegisai TO aegisai;

-- Connect to the aegisai database
\c aegisai;

-- Create agents table
CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY,
    info JSONB,
    last_seen TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20),
    registration_time TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create threats table
CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY,
    file_hash VARCHAR(64),
    name VARCHAR(255),
    type VARCHAR(50),
    severity VARCHAR(20),
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    detection_count INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create threat_intel table
CREATE TABLE IF NOT EXISTS threat_intel (
    id UUID PRIMARY KEY,
    source VARCHAR(100),
    data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create analysis_results table
CREATE TABLE IF NOT EXISTS analysis_results (
    id UUID PRIMARY KEY,
    agent_id UUID,
    file_hash VARCHAR(64),
    file_path TEXT,
    threat_level VARCHAR(20),
    detections JSONB,
    confidence REAL,
    timestamp TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_threats_file_hash ON threats(file_hash);
CREATE INDEX IF NOT EXISTS idx_threats_last_seen ON threats(last_seen);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);

-- Grant privileges to the aegisai user
GRANT ALL PRIVILEGES ON TABLE agents TO aegisai;
GRANT ALL PRIVILEGES ON TABLE threats TO aegisai;
GRANT ALL PRIVILEGES ON TABLE threat_intel TO aegisai;
GRANT ALL PRIVILEGES ON TABLE analysis_results TO aegisai;

-- Grant usage on sequences (if any)
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aegisai;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO aegisai;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO aegisai;