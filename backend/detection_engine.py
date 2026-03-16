import joblib
import os
import pickle
import pandas as pd

class DetectionEngine:
    def __init__(self, model_path='../backend/sentinel_model.pkl', config_path='../backend/supervised_config.pkl'):
        """
        Initializes the detection engine by loading the pre-trained model.
        Prioritizes the Supervised RandomForest model for accuracy.
        """
        # Adjust paths to be relative to the script location
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Check for the new pickle model first
        full_model_path = os.path.join(base_dir, model_path)
        
        # Fallback 1: Supervised Joblib model (old name)
        if not os.path.exists(full_model_path):
            model_path = '../backend/supervised_model.pkl'
            full_model_path = os.path.join(base_dir, model_path)
            
        # Fallback 2: Isolation Forest
        if not os.path.exists(full_model_path):
            model_path = '../backend/isolation_model.pkl'
            config_path = '../backend/model_config.pkl'
            full_model_path = os.path.join(base_dir, model_path)

        full_config_path = os.path.join(base_dir, config_path)

        if os.path.exists(full_model_path):
            # Check if it's a pickle file or joblib file
            if full_model_path.endswith('.pkl'):
                try:
                    with open(full_model_path, 'rb') as f:
                        self.model = pickle.load(f)
                except:
                    self.model = joblib.load(full_model_path)
            else:
                self.model = joblib.load(full_model_path)
            print(f"Loaded Machine Learning model from {full_model_path}")
        else:
            self.model = None
            print(f"Warning: Model not found at {full_model_path}.")

        if os.path.exists(full_config_path):
            self.config = joblib.load(full_config_path)
            self.features_list = self.config.get('features', [])
            print(f"Loaded model configuration with features: {self.features_list}")
        else:
            self.features_list = ["Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Packet Length Mean", "Flow Bytes/s"]
            print("Warning: Model config not found. Falling back to default CICIDS feature list.")
            
    def predict(self, features):
        """
        Predicts whether the given network features represent normal or suspicious traffic.
        
        Args:
            features (dict): Extracted features must contain:
                             packet_length, protocol, src_port, dst_port
            
        Returns:
            str: "NORMAL" or "SUSPICIOUS"
        """
        if not self.model:
            return "NORMAL"
            
        # Format the features into a DataFrame to match the training format and silence warnings
        model_input = pd.DataFrame([features], columns=self.features_list)
        
        prediction = self.model.predict(model_input)[0]
        
        # Type Check for correct mapping
        model_type = type(self.model).__name__
        
        if model_type == "IsolationForest":
            # IsolationForest: 1 is Normal, -1 is Anomaly
            if prediction == 1:
                return "NORMAL"
            else:
                return "SUSPICIOUS"
        else:
            # Supervised Models (RandomForest): 0 is Benign (Normal), 1 is Attack (Suspicious)
            if prediction == 0:
                return "NORMAL"
            else:
                return "SUSPICIOUS"

