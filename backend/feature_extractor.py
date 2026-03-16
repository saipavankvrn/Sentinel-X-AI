from scapy.all import IP, TCP, UDP

def extract_features(packet):
    """
    Extracts relevant machine learning features from a captured raw network packet.
    
    Args:
        packet: The Scapy packet object.
        
    Returns:
        dict: The extracted numerical features.
    """
    features = {
        "src_ip": None,
        "dst_ip": None,
        "packet_length": len(packet),
        "protocol": None,
        "src_port": None,
        "dst_port": None
    }
    
    if IP in packet:
        features["src_ip"] = packet[IP].src
        features["dst_ip"] = packet[IP].dst
        features["protocol"] = packet[IP].proto
        
    if TCP in packet:
        features["src_port"] = packet[TCP].sport
        features["dst_port"] = packet[TCP].dport
    elif UDP in packet:
        features["src_port"] = packet[UDP].sport
        features["dst_port"] = packet[UDP].dport
        
    return features
