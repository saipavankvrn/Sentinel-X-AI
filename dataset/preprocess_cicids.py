import pandas as pd
import numpy as np

def load_and_preprocess_dataset(filepath):
    """
    Loads and preprocesses the CICIDS2017 dataset for Sentinel-X machine learning.
    
    Args:
        filepath (str): The path to the raw CICIDS2017 CSV file.
        
    Returns:
        pd.DataFrame: The cleaned dataset ready for model training.
    """
    print(f"[INFO] Loading dataset from {filepath}...")
    try:
        df = pd.read_csv(filepath, low_memory=False)
    except Exception as e:
        print(f"[ERROR] Failed to load {filepath}: {e}")
        return None

    print(f"[INFO] Original dataset shape: {df.shape}")

    # Strip whitespace from column names (CICIDS2017 often has leading/trailing spaces)
    df.columns = df.columns.str.strip()

    # Define columns that need to be dropped (identifiers and timestamps)
    columns_to_drop = ["Flow ID", "Source IP", "Destination IP", "Timestamp"]
    
    # Drop them if they exist
    existing_cols_to_drop = [col for col in columns_to_drop if col in df.columns]
    if existing_cols_to_drop:
        df.drop(columns=existing_cols_to_drop, inplace=True)
        print(f"[INFO] Dropped unnecessary columns: {existing_cols_to_drop}")

    # Define the specific features requested for the AI model
    required_features = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Packet Length Mean",
        "Flow Bytes/s",
        "Protocol",
        "Destination Port",
        "Label"
    ]

    # Select only the requested features to avoid KeyError if names slightly mismatch
    available_features = [col for col in required_features if col in df.columns]
    
    # Handle the Label column specifically if it wasn't named perfectly
    if "Label" not in available_features:
        label_cols = [col for col in df.columns if 'label' in col.lower()]
        if label_cols:
            df.rename(columns={label_cols[0]: 'Label'}, inplace=True)
            available_features.append('Label')
            print(f"[INFO] Renamed column '{label_cols[0]}' to 'Label'")
        else:
            print("[ERROR] 'Label' column not found. Cannot set up binary classification.")
            return None

    # Filter the dataframe to only include our selected high-impact features
    df = df[available_features]
    print(f"[INFO] Selected {len(available_features) - 1} high-impact features for training.")

    # Handle missing and infinite values
    # Network metrics like 'Flow Bytes/s' often calculate to Infinity if duration was 0
    print("[INFO] Cleaning missing and infinite values...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    initial_rows = len(df)
    df.dropna(inplace=True)
    dropped_rows = initial_rows - len(df)
    
    if dropped_rows > 0:
        print(f"[INFO] Removed {dropped_rows} corrupted/missing rows.")

    # Convert the Label column into a strict binary classification
    print("[INFO] Converting labels to Binary (0 = BENIGN, 1 = ATTACK)...")
    df['Label'] = df['Label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
    
    # Print the distribution of normal vs attack traffic
    attack_count = df['Label'].sum()
    benign_count = len(df) - attack_count
    print(f"[INFO] Dataset balance: {benign_count} BENIGN, {attack_count} ATTACK records.")
    print(f"[SUCCESS] Cleaned dataset shape: {df.shape}")

    return df

if __name__ == "__main__":
    print("-" * 50)
    print("Sentinel-X: CICIDS2017 Dataset Preprocessor")
    print("-" * 50)
    
    # Example usage:
    # dataset_path = "data/CICIDS2017_raw.csv"
    # cleaned_df = load_and_preprocess_dataset(dataset_path)
    
    # if cleaned_df is not None:
    #     output_path = "data/CICIDS2017_cleaned.csv"
    #     cleaned_df.to_csv(output_path, index=False)
    #     print(f"[SUCCESS] Saved ready-to-train dataset to {output_path}")
