import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import pickle
import joblib 
from datetime import datetime

def prepare_sentinel_x_dataset(csv_path):
    """
    Loads the CICIDS2017 dataset, cleans it, and prepares it for Sentinel-X ML training.
    """
    if not os.path.exists(csv_path):
        print(f"[ERROR] Dataset file not found at: {csv_path}")
        return None

    print(f"[INFO] Loading dataset: {csv_path}")
    
    # Requirements:
    # 1. Use pandas to load the dataset
    df = pd.read_csv(csv_path, low_memory=False)
    
    # The CICIDS dataset often has leading/trailing spaces in column names
    df.columns = df.columns.str.strip()
    
    # 2. Remove unnecessary columns
    cols_to_remove = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
    df.drop(columns=[col for col in cols_to_remove if col in df.columns], inplace=True)
    
    # 3. Select important features
    target_features = [
        "Flow Duration", 
        "Total Fwd Packets", 
        "Total Backward Packets", 
        "Packet Length Mean", 
        "Flow Bytes/s", 
        "Protocol", 
        "Destination Port",
        "Label"
    ]
    
    # Filter to only these features
    df = df[[col for col in target_features if col in df.columns]]
    
    # 4. Handle missing values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # 5. Convert Label column into binary classification
    if 'Label' in df.columns:
        df['Label'] = df['Label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
    
    return df

def train_and_evaluate_model(df):
    """
    Splits the dataset, trains a Random Forest model, and evaluates performance.
    """
    if df is None: return

    features = [col for col in df.columns if col != 'Label']
    X = df[features]
    y = df['Label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("[INFO] Training RandomForest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    print("[INFO] Evaluating model performance...")
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    full_report = classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK'])

    header = "=" * 50
    results_text = f"""
==================================================
🛡️  SENTINEL-X MODEL EVALUATION REPORT
==================================================
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Dataset Size: {len(df)} samples

METRICS:
---------
✅ Accuracy:  {accuracy:.4f}
🎯 Precision: {precision:.4f}
🔍 Recall:    {recall:.4f}
📈 F1-Score:  {f1:.4f}

DETAILED CLASSIFICATION REPORT:
--------------------------------
{full_report}
==================================================
"""
    print(results_text)
    
    with open('ml/model_evaluation.txt', 'w', encoding='utf-8') as f:
        f.write(results_text)
    print(f"[SUCCESS] Metrics saved to ml/model_evaluation.txt")

    model_path = 'backend/sentinel_model.pkl'
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"[INFO] Model saved as {model_path} using pickle.")

    # Save features configuration for the DetectionEngine
    config_path = 'backend/supervised_config.pkl'
    joblib.dump({'features': features}, config_path)
    print(f"[INFO] Model config saved as {config_path}")

def retrain_model():
    """
    Adaptive Learning: Loads original dataset + live collected data and retrains the AI.
    This allows the system to evolve with new attack patterns discovered in real-world traffic.
    """
    base_path = "C:/dummy/sentinal x/sentinel-x/dataset/MachineLearningCVE/"
    monday_path = base_path + "Monday-WorkingHours.pcap_ISCX.csv"
    friday_path = base_path + "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    live_path = "dataset/live_learning.csv"
    
    print("[ADAPTIVE LEARNING] Loading original baseline data...")
    monday_df = prepare_sentinel_x_dataset(monday_path)
    if monday_df is not None:
        monday_df = monday_df.sample(n=min(50000, len(monday_df)), random_state=42)
    
    friday_df = prepare_sentinel_x_dataset(friday_path)
    
    final_df = pd.concat([monday_df, friday_df], ignore_index=True)
    
    if os.path.exists(live_path):
        print(f"[ADAPTIVE LEARNING] Found new live patterns in {live_path}. Integrating...")
        live_df = pd.read_csv(live_path)
        final_df = pd.concat([final_df, live_df], ignore_index=True)
    
    print(f"[ADAPTIVE LEARNING] Evolving model with {len(final_df)} samples...")
    train_and_evaluate_model(final_df)
    print("✅ System successfully evolved. New attack patterns have been integrated into Sentinel-X.")

if __name__ == "__main__":
    retrain_model()
