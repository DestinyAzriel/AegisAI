#!/usr/bin/env python3
"""
AegisAI Ensemble Threat Detector
===============================

This module provides an ensemble approach to threat detection by combining
multiple machine learning models for improved accuracy and robustness.
"""

import os
import json
import logging
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime
import numpy as np

# Import our enhanced detectors
from core.enhanced_ml_detector import EnhancedMLDetector
from core.behavioral_ml_analyzer import BehavioralMLAnalyzer

# Try to import additional ML libraries
try:
    from sklearn.ensemble import VotingClassifier
    from sklearn.linear_model import LogisticRegression
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    VotingClassifier = None
    LogisticRegression = None
    logging.warning("Scikit-learn not available. Install with: pip install scikit-learn")

logger = logging.getLogger(__name__)

class EnsembleThreatDetector:
    """Ensemble threat detector combining multiple ML models"""
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize the ensemble threat detector"""
        self.model_path = model_path
        self.file_detector = EnhancedMLDetector()
        self.behavioral_analyzer = BehavioralMLAnalyzer()
        self.ensemble_classifier = None
        self.is_trained = False
        self.weights = {
            'file_ml': 0.4,
            'file_heuristic': 0.2,
            'behavioral_ml': 0.3,
            'behavioral_rule': 0.1
        }
        
        # Load pre-trained models if available
        if model_path and os.path.exists(model_path):
            self.load_models()
        
        logger.info("Ensemble threat detector initialized")
    
    def detect_threat(self, filepath: str, entity_id: str = None) -> Dict[str, Any]:
        """
        Detect threats using ensemble of models
        
        Args:
            filepath: Path to the file to analyze
            entity_id: Entity ID for behavioral analysis (optional)
            
        Returns:
            Dictionary with threat detection results
        """
        try:
            # Get predictions from all models
            predictions = {}
            
            # File-based ML detection
            file_ml_result = self.file_detector.predict_file_threat(filepath)
            predictions['file_ml'] = file_ml_result
            
            # File-based heuristic detection
            file_heuristic_result = self.file_detector._heuristic_detection(filepath)
            predictions['file_heuristic'] = file_heuristic_result
            
            # Behavioral ML analysis (if entity_id provided)
            if entity_id:
                behavioral_ml_result = self.behavioral_analyzer.detect_anomalous_behavior(entity_id)
                predictions['behavioral_ml'] = behavioral_ml_result
                
                # Behavioral rule-based analysis
                behavioral_rule_result = self.behavioral_analyzer._rule_based_anomaly_detection(entity_id)
                predictions['behavioral_rule'] = behavioral_rule_result
            else:
                # Use neutral scores if no behavioral analysis
                predictions['behavioral_ml'] = {'is_anomalous': False, 'anomaly_score': 0.0}
                predictions['behavioral_rule'] = {'is_anomalous': False, 'anomaly_score': 0.0}
            
            # Combine predictions using weighted voting
            ensemble_result = self._combine_predictions(predictions)
            
            return {
                'is_threat': ensemble_result['is_threat'],
                'confidence': ensemble_result['confidence'],
                'ensemble_score': ensemble_result['ensemble_score'],
                'individual_scores': ensemble_result['individual_scores'],
                'method': 'ensemble',
                'predictions': predictions,
                'file_info': {
                    'path': filepath,
                    'exists': os.path.exists(filepath)
                }
            }
            
        except Exception as e:
            logger.error(f"Error in ensemble threat detection: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'method': 'error',
                'error': str(e)
            }
    
    def _combine_predictions(self, predictions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Combine predictions from multiple models using weighted voting
        
        Args:
            predictions: Dictionary of predictions from different models
            
        Returns:
            Dictionary with combined results
        """
        # Extract scores from each model
        individual_scores = {}
        
        # File ML score
        file_ml_pred = predictions.get('file_ml', {})
        file_ml_score = file_ml_pred.get('confidence', 0.0) if file_ml_pred.get('is_threat', False) else (1.0 - file_ml_pred.get('confidence', 0.0))
        individual_scores['file_ml'] = file_ml_score
        
        # File heuristic score
        file_heuristic_pred = predictions.get('file_heuristic', {})
        file_heuristic_score = file_heuristic_pred.get('confidence', 0.0) if file_heuristic_pred.get('is_threat', False) else (1.0 - file_heuristic_pred.get('confidence', 0.0))
        individual_scores['file_heuristic'] = file_heuristic_score
        
        # Behavioral ML score
        behavioral_ml_pred = predictions.get('behavioral_ml', {})
        behavioral_ml_score = behavioral_ml_pred.get('anomaly_score', 0.0) if behavioral_ml_pred.get('is_anomalous', False) else (1.0 - behavioral_ml_pred.get('anomaly_score', 0.0))
        individual_scores['behavioral_ml'] = behavioral_ml_score
        
        # Behavioral rule score
        behavioral_rule_pred = predictions.get('behavioral_rule', {})
        behavioral_rule_score = behavioral_rule_pred.get('anomaly_score', 0.0) if behavioral_rule_pred.get('is_anomalous', False) else (1.0 - behavioral_rule_pred.get('anomaly_score', 0.0))
        individual_scores['behavioral_rule'] = behavioral_rule_score
        
        # Calculate weighted ensemble score
        ensemble_score = 0.0
        total_weight = 0.0
        
        for model_name, score in individual_scores.items():
            weight = self.weights.get(model_name, 0.0)
            ensemble_score += score * weight
            total_weight += weight
        
        # Normalize by total weight
        if total_weight > 0:
            ensemble_score /= total_weight
        
        # Determine if it's a threat based on ensemble score
        is_threat = ensemble_score > 0.5
        confidence = ensemble_score if is_threat else (1.0 - ensemble_score)
        
        return {
            'is_threat': is_threat,
            'confidence': confidence,
            'ensemble_score': ensemble_score,
            'individual_scores': individual_scores
        }
    
    def train_ensemble(self, training_data: List[Tuple[str, str, int]]) -> Dict[str, Any]:
        """
        Train the ensemble models
        
        Args:
            training_data: List of tuples (filepath, entity_id, label) where label is 0 (clean) or 1 (malicious)
            
        Returns:
            Dictionary with training results
        """
        if not ML_AVAILABLE:
            return {'error': 'Machine learning libraries not available'}
        
        try:
            # Separate data for different models
            file_training_data = [(filepath, label) for filepath, _, label in training_data]
            behavioral_training_data = [(entity_id, 60) for _, entity_id, _ in training_data if entity_id]
            
            # Train file detector
            file_results = self.file_detector.train_file_classifier(file_training_data)
            
            # Train behavioral analyzer
            behavioral_results = self.behavioral_analyzer.train_anomaly_detector(behavioral_training_data)
            
            self.is_trained = True
            
            # Save models if path provided
            if self.model_path:
                self.save_models()
            
            return {
                'status': 'success',
                'file_training': file_results,
                'behavioral_training': behavioral_results,
                'total_samples': len(training_data)
            }
            
        except Exception as e:
            logger.error(f"Error training ensemble: {e}")
            return {'error': str(e)}
    
    def adjust_weights(self, new_weights: Dict[str, float]):
        """
        Adjust the weights for ensemble voting
        
        Args:
            new_weights: Dictionary with new weights for each model
        """
        # Validate weights sum to approximately 1.0
        total_weight = sum(new_weights.values())
        if abs(total_weight - 1.0) > 0.01:
            logger.warning(f"Weights sum to {total_weight}, not 1.0. Normalizing...")
            # Normalize weights
            normalized_weights = {k: v/total_weight for k, v in new_weights.items()}
            self.weights.update(normalized_weights)
        else:
            self.weights.update(new_weights)
        
        logger.info(f"Updated ensemble weights: {self.weights}")
    
    def get_threat_intelligence(self, filepath: str, entity_id: str = None) -> Dict[str, Any]:
        """
        Get comprehensive threat intelligence including detailed analysis
        
        Args:
            filepath: Path to the file to analyze
            entity_id: Entity ID for behavioral analysis (optional)
            
        Returns:
            Dictionary with comprehensive threat intelligence
        """
        # Get ensemble detection result
        detection_result = self.detect_threat(filepath, entity_id)
        
        # Get behavioral summary if entity_id provided
        behavioral_summary = {}
        if entity_id:
            behavioral_summary = self.behavioral_analyzer.get_behavior_summary(entity_id)
        
        # Get file features
        file_features = self.file_detector.extract_enhanced_features(filepath)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'detection_result': detection_result,
            'behavioral_summary': behavioral_summary,
            'file_features': file_features,
            'threat_intelligence': {
                'overall_assessment': 'threat' if detection_result.get('is_threat', False) else 'clean',
                'confidence_level': detection_result.get('confidence', 0.0),
                'risk_factors': self._identify_risk_factors(detection_result, behavioral_summary, file_features),
                'recommendations': self._generate_recommendations(detection_result, behavioral_summary, file_features)
            }
        }
    
    def _identify_risk_factors(self, detection_result: Dict[str, Any], 
                              behavioral_summary: Dict[str, Any], 
                              file_features: Dict[str, Any]) -> List[str]:
        """Identify key risk factors"""
        risk_factors = []
        
        # From detection result
        predictions = detection_result.get('predictions', {})
        
        # File-based risks
        file_ml_pred = predictions.get('file_ml', {})
        if file_ml_pred.get('is_threat', False) and file_ml_pred.get('confidence', 0) > 0.7:
            risk_factors.append("ML model detected high-confidence threat")
        
        file_heuristic_pred = predictions.get('file_heuristic', {})
        if file_heuristic_pred.get('is_threat', False) and file_heuristic_pred.get('confidence', 0) > 0.7:
            risk_factors.append("Heuristic analysis detected high-confidence threat")
        
        # Behavioral risks
        behavioral_ml_pred = predictions.get('behavioral_ml', {})
        if behavioral_ml_pred.get('is_anomalous', False) and behavioral_ml_pred.get('anomaly_score', 0) > 0.7:
            risk_factors.append("ML behavioral analysis detected high-confidence anomaly")
        
        behavioral_rule_pred = predictions.get('behavioral_rule', {})
        if behavioral_rule_pred.get('is_anomalous', False) and behavioral_rule_pred.get('anomaly_score', 0) > 0.7:
            risk_factors.append("Rule-based behavioral analysis detected high-confidence anomaly")
        
        # From file features
        if file_features.get('entropy', 0) > 7.5:
            risk_factors.append("High file entropy suggesting packing/encryption")
        
        if file_features.get('file_size', 0) > 100 * 1024 * 1024:  # 100MB
            risk_factors.append("Very large file size")
        
        # From behavioral summary
        anomaly_indicators = behavioral_summary.get('anomaly_indicators', [])
        high_severity_anomalies = [ind for ind in anomaly_indicators if ind.get('severity') == 'high']
        if high_severity_anomalies:
            risk_factors.append(f"{len(high_severity_anomalies)} high-severity behavioral anomalies detected")
        
        return risk_factors
    
    def _generate_recommendations(self, detection_result: Dict[str, Any], 
                                behavioral_summary: Dict[str, Any], 
                                file_features: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        is_threat = detection_result.get('is_threat', False)
        confidence = detection_result.get('confidence', 0.0)
        
        if is_threat:
            if confidence > 0.8:
                recommendations.append("Immediate quarantine recommended")
                recommendations.append("Full system scan advised")
                recommendations.append("Network isolation recommended")
            elif confidence > 0.6:
                recommendations.append("File quarantine recommended")
                recommendations.append("Behavioral monitoring advised")
            else:
                recommendations.append("Increased monitoring recommended")
                recommendations.append("Periodic re-scanning advised")
        
        # General recommendations based on features
        if file_features.get('entropy', 0) > 7.5:
            recommendations.append("Consider unpacking analysis for this file")
        
        if behavioral_summary.get('anomaly_indicators'):
            recommendations.append("Review behavioral logs for unusual patterns")
        
        # If no specific threats but high entropy or suspicious extensions
        if not is_threat:
            suspicious_extensions = ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.com']
            if file_features.get('extension', '').lower() in suspicious_extensions:
                recommendations.append("Execute in sandbox environment for safety")
        
        if not recommendations:
            recommendations.append("File appears clean based on current analysis")
            recommendations.append("Continue routine monitoring")
        
        return recommendations
    
    def save_models(self):
        """Save trained models to disk"""
        if not self.is_trained or not self.model_path:
            return
        
        try:
            model_data = {
                'timestamp': datetime.now().isoformat(),
                'weights': self.weights,
                'is_trained': self.is_trained
            }
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            
            # Save model metadata
            with open(self.model_path, 'w') as f:
                json.dump(model_data, f)
            
            # Save individual models
            file_model_path = self.model_path.replace('.json', '_file.json')
            behavioral_model_path = self.model_path.replace('.json', '_behavioral.json')
            
            self.file_detector.save_models()
            self.behavioral_analyzer.save_models()
            
            logger.info(f"Ensemble models saved to {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error saving ensemble models: {e}")
    
    def load_models(self):
        """Load trained models from disk"""
        try:
            with open(self.model_path, 'r') as f:
                model_data = json.load(f)
            
            self.is_trained = model_data.get('is_trained', False)
            self.weights = model_data.get('weights', self.weights)
            logger.info(f"Ensemble models loaded from {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error loading ensemble models: {e}")

# Example usage
if __name__ == "__main__":
    # Initialize ensemble detector
    ensemble_detector = EnsembleThreatDetector()
    
    # Test with this script file
    result = ensemble_detector.detect_threat(__file__, "test_entity_123")
    print("Ensemble Threat Detection Results:")
    print(json.dumps(result, indent=2))
    
    # Get comprehensive threat intelligence
    intelligence = ensemble_detector.get_threat_intelligence(__file__, "test_entity_123")
    print("\nComprehensive Threat Intelligence:")
    print(json.dumps(intelligence, indent=2))