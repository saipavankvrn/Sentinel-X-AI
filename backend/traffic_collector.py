import csv
import os
from scapy.all import sniff
from feature_extractor import extract_features

def collect_traffic(output_csv='../dataset/collected_traffic.csv', packet_count=1000):
    print(f"Collecting {packet_count} packets for the dataset...")
    
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    captured_data = []
    
    def packet_handler(packet):
        features = extract_features(packet)
        row = {
            "packet_length": features.get("packet_length", 0),
            "protocol": features.get("protocol") if features.get("protocol") is not None else -1,
            "src_port": features.get("src_port") if features.get("src_port") is not None else 0,
            "dst_port": features.get("dst_port") if features.get("dst_port") is not None else 0
        }
        captured_data.append(row)
        # We handle stopping via stop_filter
            
    sniff(prn=packet_handler, stop_filter=lambda p: len(captured_data) >= packet_count)
    
    print(f"Saving to {output_csv}...")
    with open(output_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["packet_length", "protocol", "src_port", "dst_port"])
        writer.writeheader()
        writer.writerows(captured_data)
        
    print("Collection complete!")

if __name__ == "__main__":
    collect_traffic()
