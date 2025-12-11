#!/usr/bin/env python3
"""
AegisAI Federated Learning Server
================================

Web server implementation for the federated learning aggregator.
"""

import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from federated_aggregator import FederatedLearningAggregator
import numpy as np

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Initialize federated learning aggregator
aggregator = FederatedLearningAggregator(model_shape=(100,), learning_rate=0.01)

@app.route('/api/v1/model', methods=['GET'])
def get_model():
    """Get current global model."""
    try:
        model_info = aggregator.get_model()
        return jsonify(model_info)
    except Exception as e:
        logger.error(f"Error getting model: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/updates', methods=['POST'])
def submit_update():
    """Submit client updates."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        client_id = data.get('client_id')
        gradients = data.get('gradients')
        metadata = data.get('metadata', {})
        
        if not client_id or not gradients:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Convert gradients to numpy array
        gradients_array = np.array(gradients)
        
        # Submit update to aggregator
        aggregator.submit_update(client_id, gradients_array, metadata)
        
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Error submitting update: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/stats', methods=['GET'])
def get_stats():
    """Get system statistics."""
    try:
        stats = aggregator.get_client_stats()
        stats['timestamp'] = datetime.now().isoformat()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/register', methods=['POST'])
def register_client():
    """Register new client."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        client_id = data.get('client_id')
        client_info = data.get('client_info', {})
        
        if not client_id:
            return jsonify({'error': 'Missing client_id'}), 400
        
        # Register client with aggregator
        aggregator.register_client(client_id, client_info)
        
        return jsonify({'status': 'success', 'client_id': client_id})
    except Exception as e:
        logger.error(f"Error registering client: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/aggregate', methods=['POST'])
def run_aggregation():
    """Run aggregation round."""
    try:
        aggregated_model = aggregator.run_aggregation_round()
        if aggregated_model:
            return jsonify({
                'status': 'success',
                'model_version': aggregated_model.version,
                'client_count': aggregated_model.client_count,
                'accuracy': aggregated_model.accuracy
            })
        else:
            return jsonify({'status': 'no_updates'}), 200
    except Exception as e:
        logger.error(f"Error running aggregation: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting federated learning server on http://localhost:8085")
    app.run(host='localhost', port=8085, debug=False)