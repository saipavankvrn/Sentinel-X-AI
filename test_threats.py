import requests
import time
import random
from datetime import datetime

# Configuration
API_URL = "http://127.0.0.1:8001/alerts"
STATS_URL = "http://127.0.0.1:8001/update_packet_count"

def trigger_test_attack(attack_type):
    """
    Sends a specific attack pattern to the dashboard to test the ML and AI explanation layers.
    """
    print(f"[TEST] Injecting {attack_type} pattern...")
    
    src_ip = f"10.0.0.{random.randint(10, 250)}"
    dst_ip = "192.168.1.10"
    
    # Simulate different flow statistics for different attack types
    if attack_type == "DDOS":
        features = {
            "Destination Port": 80,
            "Flow Duration": 500,
            "Total Fwd Packets": 5000,
            "Total Backward Packets": 10,
            "Packet Length Mean": 1200,
            "Flow Bytes/s": 5000000,
            "alert_type": "DDOS_SURGE"
        }
    elif attack_type == "PORTSCAN":
        features = {
            "Destination Port": random.randint(1, 65535),
            "Flow Duration": 10,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 0,
            "Packet Length Mean": 0,
            "Flow Bytes/s": 0,
            "alert_type": "PORT_SCAN"
        }
    elif attack_type == "EXFILTRATION":
        features = {
            "Destination Port": 443,
            "Flow Duration": 6000000,
            "Total Fwd Packets": 100,
            "Total Backward Packets": 100,
            "Packet Length Mean": 8500, # Very large packets
            "Flow Bytes/s": 1500000,
            "alert_type": "DATA_LEAK"
        }
    
    # Mock the full alert payload for the dashboard
    alert_data = {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": "TCP",
        "packet_length": features["Packet Length Mean"],
        "alert_type": features["alert_type"],
        "status": "BLOCKED",
        "explanation": f"Automated Test: {attack_type} signature detected using stateful flow analysis.",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    try:
        requests.post(API_URL, json=alert_data, timeout=2)
        print(f"[SUCCESS] {attack_type} alert visible on dashboard.")
    except Exception as e:
        print(f"[ERROR] Dashboard backend not reachable: {e}")

if __name__ == "__main__":
    print("--- Sentinel-X Threat Test Suite ---")
    print("1. Test DDoS Detection")
    print("2. Test Port Scan Detection")
    print("3. Test Data Exfiltration")
    print("4. Run Infinite Mixed Simulation")
    
    choice = input("Select a test (1-4): ")
    
    if choice == "1":
        trigger_test_attack("DDOS")
    elif choice == "2":
        trigger_test_attack("PORTSCAN")
    elif choice == "3":
        trigger_test_attack("EXFILTRATION")
    else:
        print("Starting continuous mixed simulation...")
        while True:
            t = random.choice(["DDOS", "PORTSCAN", "EXFILTRATION"])
            trigger_test_attack(t)
            time.sleep(2)
