import pandas as pd
import os
import joblib
from sklearn.ensemble import IsolationForest

MODEL_PATH = "models/anomaly_detector.pkl"
DATA_PATH = "data/port_scan_results.csv"

def load_data():
    if not os.path.exists(DATA_PATH):
        print(f"Error: {DATA_PATH} not found.")
        return None
    return pd.read_csv(DATA_PATH)

def train_model(df):
    os.makedirs("models", exist_ok=True)  # Ensure models directory exists
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(df[['port']])  # Using port numbers as features
    joblib.dump(model, MODEL_PATH)
    print("Model trained and saved!")

def detect_anomalies():
    df = load_data()
    if df is None:
        return

    if not os.path.exists(MODEL_PATH):
        print("No existing model found. Training a new one...")
        train_model(df)

    model = joblib.load(MODEL_PATH)
    df['anomaly'] = model.predict(df[['port']])

    anomalies = df[df['anomaly'] == -1]
    if not anomalies.empty:
        print("\nAnomalies Detected!\n", anomalies)
    else:
        print("\nNo anomalies detected.")

    return anomalies

if __name__ == "__main__":
    detect_anomalies()
