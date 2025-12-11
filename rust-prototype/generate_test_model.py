#!/usr/bin/env python3
"""
Generate a simple ONNX model for testing the AegisAI Rust agent.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import make_classification
import onnxruntime as ort
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

def generate_test_model():
    """Generate a simple ML model for malware detection."""
    print("Generating test model...")
    
    # Create a simple classification dataset
    X, y = make_classification(
        n_samples=1000,
        n_features=10,
        n_informative=5,
        n_redundant=2,
        n_clusters_per_class=1,
        random_state=42
    )
    
    # Train a simple Random Forest classifier
    clf = RandomForestClassifier(n_estimators=10, random_state=42)
    clf.fit(X, y)
    
    # Convert to ONNX
    initial_type = [('float_input', FloatTensorType([None, X.shape[1]]))]
    onnx_model = convert_sklearn(clf, initial_types=initial_type)
    
    # Save the model
    with open("models/test_model.onnx", "wb") as f:
        f.write(onnx_model.SerializeToString())
    
    print("Test model saved to models/test_model.onnx")
    
    # Test the model
    print("Testing the model...")
    sess = ort.InferenceSession("models/test_model.onnx")
    
    # Test with a sample input
    test_input = np.array([[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]], dtype=np.float32)
    result = sess.run(None, {'float_input': test_input})
    
    print(f"Test input: {test_input}")
    print(f"Model output: {result}")
    
    print("Model generation complete!")

if __name__ == "__main__":
    generate_test_model()