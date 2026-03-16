import requests
import time
import random
from datetime import datetime

# The URL of your FastAPI backend endpoint
API_URL = "http://127.0.0.1:8001/alerts"
STATS_URL = "http://127.0.0.1:8001/update_packet_count"

def generate_fake_alert():
    # Generate some random traffic data
    statuses = ["SAFE", "SAFE", "SAFE", "WARNING", "BLOCKED"]
    chosen_status = random.choice(statuses)
    
    # Fake IP addresses
    src_ips = ["192.168.1.45", "10.0.0.99", "45.22.11.101", "172.16.0.5"]
    dst_ips = ["192.168.1.1", "10.0.0.1", "8.8.8.8", "192.168.1.254"]
    
    # Packets
    if chosen_status == "SAFE":
        pkt_len = random.randint(64, 1500)
        a_type = "NORMAL"
        explanation = ""
    else:
        pkt_len = random.randint(1500, 9000)
        a_type = "SUSPICIOUS"
        explanation = "Simulated AI Analysis: High volume of data sent over an unusual port suggests a potential port scanning or data exfiltration attempt."
    
    # Fake packet count so the metrics go up nicely
    try:
        requests.post(STATS_URL, json={"count": random.randint(15, 85)}, timeout=1)
    except:
        pass
        
    alert = {
        "source_ip": random.choice(src_ips),
        "destination_ip": random.choice(dst_ips),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "packet_length": pkt_len,
        "alert_type": a_type,
        "status": chosen_status,
        "explanation": explanation,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    return alert

def run_simulation(interval=3):
    print("[START] Starting Sentinel-X Infinite Traffic Simulation...")
    print(f"Pumping live network traffic to {API_URL} (Ctrl+C to stop)")
    print("-" * 40)
    
    while True:
        fake_alert = generate_fake_alert()
        
        try:
            # POST the fake alert to the FastAPI server
            response = requests.post(API_URL, json=fake_alert)
            
            if response.status_code == 200:
                print(f"[LIVE] Processed {fake_alert['status']} event from {fake_alert['source_ip']}")
            else:
                print(f"[ERROR] API returned status code: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print("[ERROR] Could not connect to the API. Is FastAPI running on port 8001?")
            return
            
        time.sleep(interval)
        
if __name__ == "__main__":
    run_simulation(interval=2)
