import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

def train_on_cicids():
    dataset_dir = 'C:/dummy/sentinal x/sentinel-x/dataset/MachineLearningCVE'
    benign_file = os.path.join(dataset_dir, 'Monday-WorkingHours.pcap_ISCX.csv')
    
    if not os.path.exists(benign_file):
        print(f"[ERROR] Benign dataset not found at {benign_file}")
        return

    print(f"[INFO] Loading benign dataset for training: {benign_file}")
    
    # Load only necessary columns to save memory
    cols_to_use = [
        "Destination Port", 
        "Flow Duration", 
        "Total Fwd Packets", 
        "Total Backward Packets", 
        "Packet Length Mean", 
        "Flow Bytes/s", 
        "Label"
    ]
    
    try:
        # CICIDS column names have leading spaces sometimes
        df = pd.read_csv(benign_file, low_memory=False)
        df.columns = df.columns.str.strip()
        df = df[cols_to_use]
    except Exception as e:
        print(f"[ERROR] Failed to load dataset: {e}")
        return

    print("[INFO] Cleaning data...")
    # Clean inf/nan
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # Features for training
    features = ["Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Packet Length Mean", "Flow Bytes/s"]
    X = df[features]

    print(f"[INFO] Training Isolation Forest on {len(X)} benign samples...")
    # Contamination set low since this is nearly pure benign
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1)
    model.fit(X)

    model_path = 'C:/dummy/sentinal x/sentinel-x/backend/isolation_model.pkl'
    print(f"[INFO] Saving model to {model_path}...")
    joblib.dump(model, model_path)
    
    # Save the feature list so the sniffer knows what to provide
    feature_config = {'features': features}
    joblib.dump(feature_config, 'C:/dummy/sentinal x/sentinel-x/backend/model_config.pkl')
    
    print("[SUCCESS] Model trained on CIC-IDS 2017 data!")

if __name__ == "__main__":
    train_on_cicids()
