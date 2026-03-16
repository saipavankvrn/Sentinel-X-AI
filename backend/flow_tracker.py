import time

class FlowTracker:
    def __init__(self):
        # Key: (src_ip, dst_ip, src_port, dst_port, protocol)
        self.flows = {}
        self.id_counter = 0

    def update(self, packet_info):
        # Create a flow key (bidirectional)
        src = packet_info.get("src_ip")
        dst = packet_info.get("dst_ip")
        sp = packet_info.get("src_port")
        dp = packet_info.get("dst_port")
        proto = packet_info.get("protocol")
        length = packet_info.get("packet_length", 0)

        if not all([src, dst, sp, dp, proto]):
            return None

        # Sort IPs and ports to make key bidirectional
        key = tuple(sorted([(src, sp), (dst, dp)])) + (proto,)

        now = time.time()

        if key not in self.flows:
            self.flows[key] = {
                "start_time": now,
                "last_time": now,
                "fwd_packets": 1,
                "bwd_packets": 0,
                "fwd_bytes": length,
                "bwd_bytes": 0,
                "lengths": [length],
                "src_ip": src # Keep track of who started it
            }
        else:
            flow = self.flows[key]
            flow["last_time"] = now
            flow["lengths"].append(length)
            
            # Simple heuristic for fwd/bwd based on who started the flow
            if src == flow["src_ip"]:
                flow["fwd_packets"] += 1
                flow["fwd_bytes"] += length
            else:
                flow["bwd_packets"] += 1
                flow["bwd_bytes"] += length

        # Calculate CICIDS-like features
        flow = self.flows[key]
        duration = flow["last_time"] - flow["start_time"]
        total_packets = flow["fwd_packets"] + flow["bwd_packets"]
        total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]
        
        features = {
            "Destination Port": dp,
            "Flow Duration": int(duration * 1000000), # microseconds as in CICIDS
            "Protocol": proto,
            "Total Fwd Packets": flow["fwd_packets"],
            "Total Backward Packets": flow["bwd_packets"],
            "Packet Length Mean": sum(flow["lengths"]) / total_packets,
            "Flow Bytes/s": (total_bytes / duration) if duration > 0 else 0
        }
        
        return features
