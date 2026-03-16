import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

def train_model(dataset_path=None, model_output=None):
    """
    Loads dataset, trains the Isolation Forest algorithm, and saves the model.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if dataset_path is None:
        dataset_path = os.path.join(base_dir, 'dataset', 'collected_traffic.csv')
    if model_output is None:
        model_output = os.path.join(base_dir, 'backend', 'isolation_model.pkl')
        
    print(f"Loading dataset from {dataset_path}...")
    if not os.path.exists(dataset_path):

        print("Dataset not found. Please run traffic_collector.py to collect normal traffic.")
        return
        
    df = pd.read_csv(dataset_path)
    df.fillna(0, inplace=True)
    
    # Ensure we use exactly the 4 required features
    features = ['packet_length', 'protocol', 'src_port', 'dst_port']
    X = df[features]
    
    print("Training Isolation Forest Model for anomaly detection...")
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(X)
    
    print(f"Saving model to {model_output}...")
    joblib.dump(model, model_output)
    print("Training complete!")

if __name__ == "__main__":
    train_model()
