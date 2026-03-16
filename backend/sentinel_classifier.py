import os
import pickle
import joblib
import pandas as pd

# Path to the trained model and its configuration
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'sentinel_model.pkl')
CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'supervised_config.pkl')

class SentinelClassifier:
    def __init__(self):
        """
        Initializes the classifier by loading the pre-trained sentinel_model.pkl.
        """
        self.model = self._load_model()
        self.config = self._load_config()
        self.features_list = self.config.get('features', []) if self.config else []
        
        if self.model:
            print(f"[INFO] Sentinel-X Live Classifier initialized with {len(self.features_list)} features.")
        else:
            print("[ERROR] Sentinel-X model could not be loaded. Please ensure sentinel_model.pkl exists.")

    def _load_model(self):
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                print(f"[ERROR] Failed to load model with pickle: {e}")
                # Fallback to joblib if pickle fails
                try:
                    return joblib.load(MODEL_PATH)
                except:
                    return None
        return None

    def _load_config(self):
        if os.path.exists(CONFIG_PATH):
            return joblib.load(CONFIG_PATH)
        return None

    def classify_traffic(self, protocol, destination_port, packet_length, packet_rate):
        """
        Classifies live network traffic based on provided features.
        
        Args:
            protocol (str/int): The protocol (e.g., 'TCP', 'UDP', 6, 17)
            destination_port (int): The target port
            packet_length (int): Current packet or mean packet length
            packet_rate (float): Packets per second or Bytes per second
            
        Returns:
            dict: { status: 'SAFE'|'WARNING'|'BLOCKED', message: str }
        """
        if not self.model:
            return {"status": "SAFE", "message": "Model not loaded. Defaulting to SAFE."}

        # Mapping inputs to the high-performance CIC-IDS 2017 feature set
        # The model expects: ["Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Packet Length Mean", "Flow Bytes/s"]
        
        # We simulate the flow statistics if we only have single-packet live data
        # In a real flow, these would be aggregated. Here we provide a best-effort mapping.
        input_data = {
            "Destination Port": destination_port,
            "Flow Duration": 1000,           # Baseline micro-flow duration
            "Total Fwd Packets": 1,          # Single packet observation
            "Total Backward Packets": 1,
            "Packet Length Mean": packet_length,
            "Flow Bytes/s": packet_rate      # Interpreting packet_rate as byte throughput
        }

        # Ensure features are in the exact order the model was trained on
        try:
            # Create a DataFrame with the exact features required
            features_df = pd.DataFrame([input_data], columns=self.features_list)
            prediction = self.model.predict(features_df)[0]
        except Exception as e:
            return {"status": "SAFE", "message": f"Classification error: {e}"}

        # Classification Logic
        if prediction == 0:  # BENIGN
            return {
                "status": "SAFE",
                "message": "Traffic verified as benign. No anomalies detected."
            }
        else:  # ATTACK
            # Heuristic for WARNING vs BLOCKED based on packet rate or length
            status = "BLOCKED" if packet_rate > 5000 or packet_length > 1500 else "WARNING"
            
            # Determine possible attack type based on port and behavior
            attack_msg = self._generate_attack_message(destination_port, packet_length, packet_rate)
            
            return {
                "status": status,
                "message": attack_msg
            }

    def _generate_attack_message(self, port, length, rate):
        if port in [80, 443] and rate > 5000:
            return "Potential DDoS attack detected targeting web services (HTTP/HTTPS). High packet rate identified."
        elif length > 8000:
            return "Suspiciously large packet data detected. Potential Data Exfiltration or Buffer Overflow attempt."
        elif port in [21, 22, 23, 3389]:
            return f"Anomalous behavior detected on management port {port}. Possible Brute Force or unauthorized access attempt."
        else:
            return f"Unusual traffic pattern observed on port {port}. Traffic signature deviates from baseline network behavior."

# Global instance for easy importing
classifier = SentinelClassifier()

def get_classifier():
    return classifier

if __name__ == "__main__":
    # Quick Test
    test_classifier = SentinelClassifier()
    
    print("--- Test: Safe Traffic ---")
    print(test_classifier.classify_traffic("TCP", 443, 64, 100))
    
    print("\n--- Test: High Rate Traffic (DDoS) ---")
    print(test_classifier.classify_traffic("TCP", 80, 1200, 10000))
    
    print("\n--- Test: Large Packets (Exfiltration) ---")
    print(test_classifier.classify_traffic("UDP", 53, 9000, 500))
