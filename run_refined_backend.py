#!/usr/bin/env python3
"""
AegisAI Refined Backend Runner
=============================

Script to start the refined AegisAI backend components.
"""

import asyncio
import logging
import sys
import os
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def main():
    """Main function to run the refined backend."""
    logger.info("Starting AegisAI Refined Backend...")
    
    # Initialize admin_interface to None to avoid unbound variable error
    admin_interface = None

    try:
        # Import the backend manager
        from cloud.refined_backend_manager import BackendManager, AdminInterface

        # Create backend manager
        manager = BackendManager()

        # Create admin interface
        admin_interface = AdminInterface(manager, 'localhost', 8083)
        await admin_interface.start()

        logger.info("AegisAI Refined Backend started successfully!")
        logger.info("Admin interface available at: http://localhost:8083")
        logger.info("Press Ctrl+C to stop the backend")

        # Start the backend components
        await manager.start()

    except ImportError as e:
        logger.error(f"Failed to import backend components: {e}")
        logger.error("Make sure all dependencies are installed and the code is properly structured.")
        return 1
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1
    finally:
        # Cleanup
        if admin_interface is not None:
            try:
                # Stop admin interface
                await admin_interface.stop()
            except:
                pass

        logger.info("AegisAI Refined Backend stopped.")

    return 0

if __name__ == "__main__":
    # Run the main function
    exit_code = asyncio.run(main())
    sys.exit(exit_code)