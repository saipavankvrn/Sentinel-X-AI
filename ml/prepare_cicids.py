import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import pickle
import joblib # Keeping joblib for other potential uses, but will use pickle for the model as requested

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
    # Explicitly removing requested columns if they exist
    cols_to_remove = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
    df.drop(columns=[col for col in cols_to_remove if col in df.columns], inplace=True)
    
    # 3. Select important features
    # Requirements list: Flow Duration, Total Fwd Packets, Total Backward Packets, 
    # Packet Length Mean, Flow Bytes/s, Protocol, Destination Port
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
    
    # Filter to only these features (plus Label for classification)
    df = df[[col for col in target_features if col in df.columns]]
    
    # 4. Handle missing values
    # Replace inf with nan and then drop nan
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # 5. Convert Label column into binary classification
    # BENIGN = 0, ATTACK = 1
    if 'Label' in df.columns:
        print("[INFO] Converting labels to binary (BENIGN=0, ATTACK=1)...")
        df['Label'] = df['Label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
    
    print(f"[SUCCESS] Dataset prepared. Shape: {df.shape}")
    return df

def load_model(model_path='c:/dummy/sentinal x/sentinel-x/backend/sentinel_model.pkl'):
    """
    Loads the saved Sentinel-X model using pickle.
    """
    if os.path.exists(model_path):
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        print(f"[INFO] Model loaded successfully from {model_path}")
        return model
    else:
        print(f"[ERROR] Model file not found at {model_path}")
        return None

def train_and_evaluate_model(df):
    """
    Splits the dataset, trains a Random Forest model, and evaluates performance.
    """
    if df is None:
        return

    # 1. Feature/Target Selection
    # Labels were converted to 0/1 in prepare_sentinel_x_dataset
    features = [col for col in df.columns if col != 'Label']
    X = df[features]
    y = df['Label']

    # 2. Split dataset into training and testing sets (80/20)
    print(f"[INFO] Splitting dataset (80% Train / 20% Test)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Train the model (RandomForest)
    print("[INFO] Training RandomForest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    # 4. Evaluate the model
    print("[INFO] Evaluating model performance...")
    y_pred = model.predict(X_test)

    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    # 5. Print evaluation results
    print("-" * 40)
    print("🚀 SENTINEL-X MODEL EVALUATION")
    print("-" * 40)
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print("-" * 40)
    print("\nDetailed Report:")
    print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK']))
    
    # Save the model using pickle
    model_path = 'c:/dummy/sentinal x/sentinel-x/backend/sentinel_model.pkl'
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"[INFO] Model saved as {model_path} using pickle.")

if __name__ == "__main__":
    base_path = "C:/dummy/sentinal x/sentinel-x/dataset/MachineLearningCVE/"
    monday_path = base_path + "Monday-WorkingHours.pcap_ISCX.csv"
    friday_path = base_path + "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    
    if os.path.exists(monday_path) and os.path.exists(friday_path):
        print("[INFO] Preparing balanced dataset (Benign + Attack)...")
        
        # Load Benign (Sampling 100k rows to keep it fast/save memory)
        benign_df = prepare_sentinel_x_dataset(monday_path)
        if benign_df is not None:
            benign_df = benign_df.sample(n=min(100000, len(benign_df)), random_state=42)
        
        # Load Attack
        attack_df = prepare_sentinel_x_dataset(friday_path)
        
        # Combine
        combined_df = pd.concat([benign_df, attack_df], ignore_index=True)
        print(f"[INFO] Combined Dataset ready. Total rows: {len(combined_df)}")
        
        # Train and Evaluate
        train_and_evaluate_model(combined_df)
    else:
        print("[!] Dataset files not found. Ensure Monday and Friday-Afternoon-DDoS CSVs are in the dataset folder.")
