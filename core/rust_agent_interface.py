"""
AegisAI Rust Agent Interface
============================

This module provides a Python interface to communicate with the Rust endpoint agent,
enabling seamless integration between the Rust protection layer and Python core engine.
"""

import os
import json
import logging
import subprocess
import threading
import time
from typing import Dict, List, Optional, Callable, Any
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class RustAgentInterface:
    """Interface for communicating with the Rust endpoint agent."""
    
    def __init__(self, agent_path: Optional[str] = None, config_path: Optional[str] = None):
        """
        Initialize the Rust agent interface.
        
        Args:
            agent_path: Path to the Rust agent executable
            config_path: Path to the agent configuration file
        """
        self.agent_path = agent_path or self._find_agent_executable()
        self.config_path = config_path
        self.agent_process: Optional[subprocess.Popen] = None
        self.is_running = False
        self.callbacks = {}
        self.pending_requests = {}  # Track pending requests for synchronous responses
        self.request_counter = 0
        self.message_handlers = {
            'threat_detected': self._handle_threat_detected,
            'scan_complete': self._handle_scan_complete,
            'update_status': self._handle_update_status,
            'health_status': self._handle_health_status,
            'log_message': self._handle_log_message,
            'status': self._handle_status,
            'model_info': self._handle_model_info
        }
        
        # Performance optimization: batch processing queue
        self.batch_queue = []
        self.batch_timer = None
        self.batch_timeout = 0.1  # 100ms batch timeout
        
        # Set up logging
        self.logger = logging.getLogger(__name__)
    
    def _find_agent_executable(self) -> Optional[str]:
        """
        Find the Rust agent executable.
        
        Returns:
            Path to the agent executable or None if not found
        """
        # Common locations to look for the agent
        possible_paths = [
            Path("rust-prototype/target/release/aegisai-agent"),
            Path("rust-prototype/target/debug/aegisai-agent"),
            Path("aegisai-agent"),
            Path("agent/aegisai-agent")
        ]
        
        for path in possible_paths:
            if path.exists():
                return str(path.absolute())
        
        # Don't try to build the agent automatically
        # Work in simulation mode instead
        logger.warning("Rust agent executable not found")
        logger.warning("Running in simulation mode - core protection features will be limited")
        return None
    
    def _build_agent(self):
        """Build the Rust agent executable."""
        logger.info("Building Rust agent...")
        
        # Change to rust-prototype directory
        rust_dir = Path("rust-prototype")
        if not rust_dir.exists():
            raise FileNotFoundError("Rust prototype directory not found")
        
        # Run cargo build
        result = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=rust_dir,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Failed to build Rust agent: {result.stderr}")
        
        logger.info("Rust agent built successfully")
    
    def start_agent(self) -> bool:
        """
        Start the Rust agent process.
        
        Returns:
            True if agent started successfully, False otherwise
        """
        # If we're in simulation mode (agent_path is None), return True
        if self.agent_path is None:
            logger.info("Running in simulation mode - Rust agent not available")
            self.is_running = True
            return True
            
        if self.is_running:
            logger.warning("Agent is already running")
            return True
        
        try:
            # Prepare command arguments
            cmd = [self.agent_path]
            if self.config_path:
                cmd.extend(["--config", self.config_path])
            
            # Start the agent process with optimized settings
            self.agent_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.is_running = True
            logger.info(f"Rust agent started with PID {self.agent_process.pid}")
            
            # Start output monitoring threads
            self._start_output_monitoring()
            
            # Wait a moment for the agent to initialize
            time.sleep(2)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Rust agent: {e}")
            self.is_running = False
            return False
    
    def stop_agent(self):
        """Stop the Rust agent process."""
        if not self.is_running:
            logger.warning("Agent is not running")
            return
        
        try:
            if self.agent_process:
                # Send shutdown signal
                self.agent_process.terminate()
                
                # Wait for graceful shutdown
                try:
                    self.agent_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # Force kill if not shutting down gracefully
                    self.agent_process.kill()
                    self.agent_process.wait()
            
            self.is_running = False
            logger.info("Rust agent stopped")
            
        except Exception as e:
            logger.error(f"Error stopping Rust agent: {e}")
    
    def _start_output_monitoring(self):
        """Start monitoring threads for agent output."""
        # Start stdout monitoring
        stdout_thread = threading.Thread(target=self._monitor_stdout, daemon=True)
        stdout_thread.start()
        
        # Start stderr monitoring
        stderr_thread = threading.Thread(target=self._monitor_stderr, daemon=True)
        stderr_thread.start()
    
    def _monitor_stdout(self):
        """Monitor stdout from the agent process."""
        if not self.agent_process or not self.agent_process.stdout:
            return
        
        try:
            for line in iter(self.agent_process.stdout.readline, ''):
                if line:
                    self._process_agent_output(line.strip())
        except Exception as e:
            logger.error(f"Error monitoring stdout: {e}")
    
    def _monitor_stderr(self):
        """Monitor stderr from the agent process."""
        if not self.agent_process or not self.agent_process.stderr:
            return
        
        try:
            for line in iter(self.agent_process.stderr.readline, ''):
                if line:
                    logger.error(f"Agent stderr: {line.strip()}")
        except Exception as e:
            logger.error(f"Error monitoring stderr: {e}")
    
    def _process_agent_output(self, output: str):
        """
        Process output from the agent.
        
        Args:
            output: Line of output from the agent
        """
        try:
            # Try to parse as JSON
            if output.startswith('{') and output.endswith('}'):
                message = json.loads(output)
                self._handle_agent_message(message)
            else:
                # Treat as log message
                self._handle_log_message({'message': output, 'level': 'info'})
        except json.JSONDecodeError:
            # Not JSON, treat as log message
            self._handle_log_message({'message': output, 'level': 'info'})
        except Exception as e:
            logger.error(f"Error processing agent output: {e}")
    
    def _handle_agent_message(self, message: Dict):
        """
        Handle a message from the agent.
        
        Args:
            message: Message dictionary from the agent
        """
        msg_type = message.get('type')
        data = message.get('data', {})
        
        if msg_type in self.message_handlers:
            try:
                self.message_handlers[msg_type](data)
            except Exception as e:
                logger.error(f"Error handling message type {msg_type}: {e}")
        else:
            logger.warning(f"Unknown message type from agent: {msg_type}")
    
    def _handle_threat_detected(self, data: Dict):
        """Handle threat detected message."""
        logger.info(f"Threat detected: {data}")
        if 'threat_detected' in self.callbacks:
            self.callbacks['threat_detected'](data)
    
    def _handle_scan_complete(self, data: Dict):
        """Handle scan complete message."""
        logger.info(f"Scan complete: {data}")
        if 'scan_complete' in self.callbacks:
            self.callbacks['scan_complete'](data)
    
    def _handle_update_status(self, data: Dict):
        """Handle update status message."""
        logger.info(f"Update status: {data}")
        if 'update_status' in self.callbacks:
            self.callbacks['update_status'](data)
    
    def _handle_health_status(self, data: Dict):
        """Handle health status message."""
        logger.info(f"Health status: {data}")
        if 'health_status' in self.callbacks:
            self.callbacks['health_status'](data)
    
    def _handle_status(self, data: Dict):
        """Handle general status message."""
        logger.info(f"Agent status: {data}")
        if 'status' in self.callbacks:
            self.callbacks['status'](data)
    
    def _handle_model_info(self, data: Dict):
        """Handle model info message."""
        logger.info(f"Model info: {data}")
        if 'model_info' in self.callbacks:
            self.callbacks['model_info'](data)
    
    def _handle_log_message(self, data: Dict):
        """Handle log message."""
        level = data.get('level', 'info')
        message = data.get('message', '')
        logger.log(getattr(logging, level.upper(), logging.INFO), f"Agent: {message}")
    
    def _batch_send_commands(self):
        """Send batched commands to the agent."""
        if not self.batch_queue:
            return
            
        # Send all queued commands
        for message_str in self.batch_queue:
            try:
                if self.agent_process and self.agent_process.stdin:
                    self.agent_process.stdin.write(message_str)
                    self.agent_process.stdin.flush()
                else:
                    logger.error("Agent process or stdin not available")
            except Exception as e:
                logger.error(f"Failed to send batched command to agent: {e}")
        
        # Clear the queue
        self.batch_queue.clear()
        self.batch_timer = None
    
    def send_command(self, command: str, data: Optional[Dict] = None, timeout: int = 30) -> Dict:
        """
        Send a command to the agent and wait for response.
        
        Args:
            command: Command to send
            data: Optional data to send with command
            timeout: Timeout in seconds to wait for response
            
        Returns:
            Response dictionary from the agent
        """
        if not self.is_running or not self.agent_process:
            logger.error("Agent is not running")
            return {'error': 'Agent not running'}
        
        # Check if stdin is available
        if not self.agent_process.stdin:
            logger.error("Agent stdin is not available")
            return {'error': 'Agent stdin not available'}
        
        # Create request ID for tracking
        request_id = self.request_counter
        self.request_counter += 1
        
        try:
            message = {
                'command': command,
                'data': data or {},
                'timestamp': datetime.now().isoformat(),
                'request_id': request_id
            }
            
            # Set up response tracking
            response_event = threading.Event()
            response_data = {}
            
            def response_handler(data):
                nonlocal response_data
                response_data = data
                response_event.set()
            
            self.pending_requests[request_id] = response_handler
            
            # Send command with batching for better performance
            message_str = json.dumps(message) + '\n'
            
            # Add to batch queue for better I/O performance
            self.batch_queue.append(message_str)
            
            # Start batch timer if not already running
            if self.batch_timer is None:
                self.batch_timer = threading.Timer(self.batch_timeout, self._batch_send_commands)
                self.batch_timer.start()
            elif len(self.batch_queue) > 10:  # Force send if queue is large
                self._batch_send_commands()
            
            # Wait for response
            if response_event.wait(timeout=timeout):
                return response_data
            else:
                logger.error(f"Timeout waiting for response to command: {command}")
                return {'error': 'timeout', 'command': command}
                
        except Exception as e:
            logger.error(f"Failed to send command to agent: {e}")
            return {'error': str(e)}
        finally:
            # Clean up pending request
            if request_id in self.pending_requests:
                del self.pending_requests[request_id]
    
    def scan_file(self, file_path: str) -> Dict:
        """
        Request the agent to scan a file.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            Response dictionary from the agent
        """
        return self.send_command('scan_file', {'path': file_path})
    
    def scan_directory(self, dir_path: str, recursive: bool = True) -> Dict:
        """
        Request the agent to scan a directory.
        
        Args:
            dir_path: Path to directory to scan
            recursive: Whether to scan subdirectories recursively
            
        Returns:
            Response dictionary from the agent
        """
        return self.send_command('scan_directory', {
            'path': dir_path,
            'recursive': recursive
        })
    
    def start_realtime_protection(self) -> Dict:
        """
        Request the agent to start real-time protection.
        
        Returns:
            Response dictionary from the agent
        """
        return self.send_command('start_realtime')
    
    def stop_realtime_protection(self) -> Dict:
        """
        Request the agent to stop real-time protection.
        
        Returns:
            Response dictionary from the agent
        """
        return self.send_command('stop_realtime')
    
    def update_configuration(self, config: Dict) -> Dict:
        """
        Update agent configuration.
        
        Args:
            config: New configuration dictionary
            
        Returns:
            Response dictionary from the agent
        """
        return self.send_command('update_config', config)
    
    def check_for_updates(self) -> Dict:
        """
        Request the agent to check for updates.
        
        Returns:
            Response dictionary from the agent
        """
        return self.send_command('check_updates')
    
    def get_agent_status(self) -> Dict:
        """
        Get current agent status.
        
        Returns:
            Response dictionary with agent status information
        """
        response = self.send_command('status')
        return {
            'running': self.is_running,
            'pid': self.agent_process.pid if self.agent_process else None,
            'agent_path': self.agent_path,
            'config_path': self.config_path,
            'agent_response': response
        }
    
    def get_model_info(self) -> Dict:
        """
        Get ML model information from the agent.
        
        Returns:
            Response dictionary with model information
        """
        return self.send_command('get_model_info')
    
    def register_callback(self, event_type: str, callback: Callable):
        """
        Register a callback for agent events.
        
        Args:
            event_type: Type of event to listen for
            callback: Function to call when event occurs
        """
        self.callbacks[event_type] = callback

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create agent interface
    agent_interface = RustAgentInterface()
    
    # Register callbacks
    def on_threat_detected(data):
        print(f"THREAT DETECTED: {data}")
    
    def on_scan_complete(data):
        print(f"SCAN COMPLETE: {data}")
    
    agent_interface.register_callback('threat_detected', on_threat_detected)
    agent_interface.register_callback('scan_complete', on_scan_complete)
    
    # Start agent
    if agent_interface.start_agent():
        print("Agent started successfully")
        
        # Wait a moment for agent to initialize
        time.sleep(2)
        
        # Send a test command
        status = agent_interface.get_agent_status()
        print(f"Agent status: {status}")
        
        # Get model info
        model_info = agent_interface.get_model_info()
        print(f"Model info: {model_info}")
        
        # Keep running for a while
        try:
            time.sleep(30)
        except KeyboardInterrupt:
            print("Stopping agent...")
            agent_interface.stop_agent()