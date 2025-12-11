"""
Database Initialization Script for AegisAI Cloud Backend
"""
import asyncpg
import asyncio
import os
from datetime import datetime

async def create_database():
    """Create the AegisAI database and tables"""
    # Connect to PostgreSQL server
    conn = await asyncpg.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        port=os.getenv('DB_PORT', 5432),
        user=os.getenv('DB_USER', 'postgres'),
        password=os.getenv('DB_PASSWORD', 'postgres')
    )
    
    try:
        # Create database if it doesn't exist
        await conn.execute("CREATE DATABASE aegisai")
        print("Database 'aegisai' created successfully")
    except asyncpg.DuplicateDatabaseError:
        print("Database 'aegisai' already exists")
    except Exception as e:
        print(f"Error creating database: {e}")
    
    await conn.close()
    
    # Connect to the AegisAI database
    conn = await asyncpg.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        port=os.getenv('DB_PORT', 5432),
        user=os.getenv('DB_USER', 'aegisai'),
        password=os.getenv('DB_PASSWORD', 'aegisai_password'),
        database=os.getenv('DB_NAME', 'aegisai')
    )
    
    try:
        # Create agents table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                id UUID PRIMARY KEY,
                info JSONB,
                last_seen TIMESTAMP WITH TIME ZONE,
                status VARCHAR(20),
                registration_time TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        """)
        print("Agents table created successfully")
        
        # Create threats table
        await conn.execute("""
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
            )
        """)
        print("Threats table created successfully")
        
        # Create threat_intel table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel (
                id UUID PRIMARY KEY,
                source VARCHAR(100),
                data JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        """)
        print("Threat intelligence table created successfully")
        
        # Create analysis_results table
        await conn.execute("""
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
            )
        """)
        print("Analysis results table created successfully")
        
        # Create indexes
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_threats_file_hash ON threats(file_hash)
        """)
        
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_threats_last_seen ON threats(last_seen)
        """)
        
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)
        """)
        
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen)
        """)
        
        print("Database indexes created successfully")
        
    except Exception as e:
        print(f"Error creating tables: {e}")
    finally:
        await conn.close()

if __name__ == '__main__':
    asyncio.run(create_database())