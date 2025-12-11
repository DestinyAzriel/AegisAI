#!/usr/bin/env python3
"""
AegisAI Graph Analytics Server
=============================

Web server implementation for the graph analytics pipeline.
"""

import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from graph_analytics_pipeline import GraphAnalyticsPipeline, ThreatEvent

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Initialize graph analytics pipeline
pipeline = GraphAnalyticsPipeline()

# In-memory storage for devices (since the pipeline doesn't have device registration)
registered_devices = {}

@app.route('/api/v1/register', methods=['POST'])
def register_device():
    """Register new device."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract device_id from device_info or directly from data
        device_id = data.get('device_id')
        if not device_id:
            device_info = data.get('device_info', {})
            device_id = device_info.get('device_id')
        
        if not device_id:
            return jsonify({'error': 'Missing device_id'}), 400
        
        # Store device registration
        registered_devices[device_id] = {
            'device_info': data.get('device_info', {}),
            'registration_time': datetime.now().isoformat()
        }
        
        return jsonify({'status': 'success', 'device_id': device_id})
    except Exception as e:
        logger.error(f"Error registering device: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/events', methods=['POST'])
def submit_events():
    """Submit threat/behavioral events."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        events_data = data.get('events', [])
        
        if not events_data:
            return jsonify({'error': 'No events provided'}), 400
        
        # Convert events data to ThreatEvent objects
        events = []
        for event_data in events_data:
            # Convert timestamp string to datetime object
            timestamp_str = event_data.get('timestamp')
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except ValueError:
                    timestamp = datetime.now()
            else:
                timestamp = datetime.now()
            
            event = ThreatEvent(
                event_id=event_data.get('event_id', f"event_{hash(str(event_data))}"),
                file_hash=event_data.get('file_hash', ''),
                device_id=event_data.get('device_id', ''),
                timestamp=timestamp,
                threat_type=event_data.get('threat_type', 'unknown'),
                severity=event_data.get('severity', 'medium'),
                file_path=event_data.get('file_path', ''),
                process_id=event_data.get('process_id'),
                parent_process_id=event_data.get('parent_process_id'),
                network_connections=event_data.get('network_connections')
            )
            events.append(event)
        
        # Process events with pipeline
        pipeline.process_threat_events(events)
        
        # Run campaign detection
        campaigns = pipeline.run_campaign_detection()
        
        return jsonify({
            'status': 'success', 
            'events_processed': len(events),
            'campaigns_detected': len(campaigns)
        })
    except Exception as e:
        logger.error(f"Error submitting events: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/campaigns', methods=['GET'])
def get_campaigns():
    """Get detected campaigns."""
    try:
        # Run campaign detection to get latest results
        campaigns = pipeline.run_campaign_detection()
        
        # Convert campaigns to serializable format
        campaigns_data = []
        for campaign in campaigns:
            campaigns_data.append({
                'campaign_id': campaign.campaign_id,
                'devices_involved': campaign.devices_involved,
                'files_involved': campaign.files_involved,
                'start_time': campaign.start_time.isoformat(),
                'end_time': campaign.end_time.isoformat(),
                'confidence': campaign.confidence,
                'description': campaign.description,
                'event_count': len(campaign.threat_events)
            })
        
        return jsonify({
            'campaigns': campaigns_data,
            'count': len(campaigns_data),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting campaigns: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/graph', methods=['GET'])
def get_graph():
    """Get graph data for visualization."""
    try:
        # Export graph to a temporary file and read it
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.graphml', delete=False) as f:
            temp_filename = f.name
        
        try:
            pipeline.export_graph(temp_filename)
            
            # Read the exported graph file
            with open(temp_filename, 'r') as f:
                graph_data = f.read()
            
            # Clean up temporary file
            os.unlink(temp_filename)
            
            return jsonify({
                'graph': graph_data,
                'format': 'graphml',
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            # Clean up temporary file if it exists
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)
            raise e
            
    except Exception as e:
        logger.error(f"Error getting graph data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/stats', methods=['GET'])
def get_stats():
    """Get system statistics."""
    try:
        stats = pipeline.get_pipeline_statistics()
        stats['timestamp'] = datetime.now().isoformat()
        stats['registered_devices'] = len(registered_devices)
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting graph analytics server on http://localhost:8086")
    app.run(host='localhost', port=8086, debug=False)