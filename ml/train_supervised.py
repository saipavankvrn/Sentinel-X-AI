import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import pickle
import joblib
import os

def load_model(model_path=None):
    """
    Utility function to load the saved Sentinel-X model.
    """
    if model_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        model_path = os.path.join(base_dir, 'backend', 'sentinel_model.pkl')
    
    if os.path.exists(model_path):
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        return model
    return None

def train_supervised_classifier():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_dir = os.path.join(base_dir, 'dataset', 'MachineLearningCVE')
    benign_file = os.path.join(dataset_dir, 'Monday-WorkingHours.pcap_ISCX.csv')
    attack_file = os.path.join(dataset_dir, 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')
    
    if not os.path.exists(benign_file) or not os.path.exists(attack_file):
        print("[ERROR] Required dataset files not found.")
        return

    print("[INFO] Loading datasets...")
    
    cols_to_use = [
        "Destination Port", 
        "Flow Duration", 
        "Total Fwd Packets", 
        "Total Backward Packets", 
        "Packet Length Mean", 
        "Flow Bytes/s", 
        "Protocol",
        "Label"
    ]
    
    # Load Benign data (sampling to save memory)
    df_benign = pd.read_csv(benign_file, low_memory=False)
    df_benign.columns = df_benign.columns.str.strip()
    df_benign = df_benign[cols_to_use].sample(n=min(50000, len(df_benign)), random_state=42)
    
    # Load Attack data
    df_attack = pd.read_csv(attack_file, low_memory=False)
    df_attack.columns = df_attack.columns.str.strip()
    df_attack = df_attack[cols_to_use]
    
    # Merge datasets
    df = pd.concat([df_benign, df_attack], ignore_index=True)
    
    print(f"[INFO] Combined dataset size: {len(df)}")
    
    # Preprocessing
    print("[INFO] Cleaning data...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # Binary labels: BENIGN=0, anything else=1
    df['Label'] = df['Label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
    
    # Feature/Target split
    features = ["Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Packet Length Mean", "Flow Bytes/s", "Protocol"]
    X = df[features]
    y = df['Label']
    
    # Train/Test split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print(f"[INFO] Training set size: {len(X_train)}")
    print(f"[INFO] Testing set size: {len(X_test)}")
    
    # Model: RandomForestClassifier
    print("[INFO] Training RandomForest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    # Evaluation
    print("[INFO] Evaluating model...")
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print("-" * 30)
    print("EVALUATION RESULTS")
    print("-" * 30)
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print("-" * 30)
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))
    
    # Save the model
    model_path = os.path.join(base_dir, 'backend', 'sentinel_model.pkl')
    print(f"[INFO] Saving model to {model_path}...")
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    # Save feature config (using joblib as it's cleaner for simple dicts)
    config_path = os.path.join(base_dir, 'backend', 'supervised_config.pkl')
    joblib.dump({'features': features}, config_path)
    
    print("[SUCCESS] Supervised classifier trained and evaluated!")

if __name__ == "__main__":
    train_supervised_classifier()
