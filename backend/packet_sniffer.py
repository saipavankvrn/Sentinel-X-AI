import requests, time
from datetime import datetime
from scapy.all import sniff
from feature_extractor import extract_features
from detection_engine import DetectionEngine
from response_engine import block_ip
from flow_tracker import FlowTracker

# Initialize the Machine Learning Detection Engine
engine = DetectionEngine()
tracker = FlowTracker()

# Keep track of IPs we have already blocked to prevent spamming the firewall/API
blocked_ips = set()

API_URL = "http://127.0.0.1:8001/alerts"
STATS_URL = "http://127.0.0.1:8001/update_packet_count"
LIVE_DATA_PATH = "c:/dummy/sentinal x/sentinel-x/dataset/live_learning.csv"

# Global counter for network packets
packet_counter = 0

def packet_callback(packet):
    """
    Callback function that processes each sniffed packet.
    """
    global packet_counter
    packet_counter += 1
    start_time = time.time() # Start Latency Tracking
    
    # 1. Extract the required machine learning features
    features = extract_features(packet)
    
    # Update backend stats every 50 packets to save API calls
    if packet_counter % 50 == 0:
        try:
            requests.post(STATS_URL, json={"count": 50}, timeout=1)
        except:
            pass
            
    # Stop processing if it's not IP traffic
    src_ip = features.get("src_ip")
    if not src_ip:
        return
        
    # Ignore if we've already dealt with this IP
    if src_ip in blocked_ips:
        return
        
    # 2. Update Flow State and get CICIDS-ready features
    flow_features = tracker.update(features)
    if not flow_features:
        return

    # 3. Ask the Machine Learning model if this packet is an anomaly
    prediction = engine.predict(flow_features)
    
    # Map protocol number to string
    proto_num = features.get("protocol", -1)
    protocol_str = "TCP" if proto_num == 6 else "UDP" if proto_num == 17 else "ICMP" if proto_num == 1 else "Unknown"

    if prediction == "SUSPICIOUS":
        print(f"🚨 [ALERT] Suspicious flow detected from {src_ip}!")
        
        # 4. Generate human-readable AI explanation
        from gemini_explainer import get_threat_explanation
        explainer_context = {**features, **flow_features}
        explanation = get_threat_explanation(explainer_context)
        
        # 6. Activate the Response Engine to physically block the malicious IP
        block_success = block_ip(src_ip)
        
        # Calculate Latency (Time from capture to response trigger)
        latency_ms = (time.time() - start_time) * 1000
        print(f"Detection Latency: {latency_ms:.2f} ms")

        alert_data = {
            "source_ip": src_ip,
            "destination_ip": features.get("dst_ip", "Unknown"),
            "protocol": protocol_str,
            "packet_length": features.get("packet_length", 0),
            "alert_type": "THREAT_DETECTED",
            "status": "BLOCKED",
            "explanation": explanation,
            "latency": latency_ms,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        if not block_success:
            # If blocking failed (e.g. no admin rights), update the alert status to WARNING
            update_data = {**alert_data, "status": "WARNING", "explanation": f"{explanation} (Note: Automatic firewall block failed. Please check permissions.)"}
            try:
                requests.post(API_URL, json=update_data, timeout=1)
            except:
                pass
            
        # Add to the set so we don't trigger the firewall rule 10,000 times
        blocked_ips.add(src_ip)
    
    else:
        # Sampling "SAFE" traffic so the dashboard feels alive
        # Send 1 normal packet for every 50 normal packets captured
        if packet_counter % 50 == 0:
            alert_data = {
                "source_ip": src_ip,
                "destination_ip": features.get("dst_ip", "Unknown"),
                "protocol": protocol_str,
                "packet_length": features.get("packet_length", 0),
                "alert_type": "BENIGN_TRAFFIC",
                "status": "SAFE",
                "explanation": "Traffic verified safe by Sentinel-X AI. No malicious signatures found.",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            try:
                requests.post(API_URL, json=alert_data, timeout=1)
            except:
                pass
    
    # Adaptive Learning: Save features for future retraining
    save_live_data(flow_features, 1 if prediction == "SUSPICIOUS" else 0)

def save_live_data(features, label):
    """
    Appends live traffic features to a local CSV for adaptive learning.
    """
    import csv, os
    file_exists = os.path.isfile(LIVE_DATA_PATH)
    
    # We only save these specific features to match the CICIDS training requirements
    row_data = {
        "Flow Duration": features.get("Flow Duration", 0),
        "Total Fwd Packets": features.get("Total Fwd Packets", 0),
        "Total Backward Packets": features.get("Total Backward Packets", 0),
        "Packet Length Mean": features.get("Packet Length Mean", 0),
        "Flow Bytes/s": features.get("Flow Bytes/s", 0),
        "Protocol": features.get("Protocol", 0),
        "Destination Port": features.get("Destination Port", 0),
        "Label": label
    }
    
    try:
        with open(LIVE_DATA_PATH, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=row_data.keys())
            if not file_exists:
                writer.writeheader()
            writer.writerow(row_data)
    except:
        pass

def start_sniffing(interface=None):
    """
    Starts packet sniffing on the specified network interface.
    """
    print(f"[START] Starting Sentinel-X Packet Sniffer on {interface if interface else 'default interface'}...")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffing()
