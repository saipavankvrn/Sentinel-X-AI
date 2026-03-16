import platform
import subprocess

def block_attacker_ip(ip_address):
    """
    Automatically blocks a malicious IP address using the system's firewall.
    
    Args:
        ip_address (str): The suspicious IP to block.
        
    Returns:
        bool: True if successfully blocked, False otherwise.
    """
    print(f"Blocking attacker IP: {ip_address}")
    
    current_os = platform.system().lower()
    
    try:
        if current_os == "linux":
            # Execute Linux iptables block rule
            # Note: The script must be run with sudo/root privileges for this to work
            cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"✅ Successfully blocked {ip_address} via Linux iptables.")
            return True
            
        elif current_os == "windows":
            # Execute Windows netsh firewall rule
            # Note: The script must be run as Administrator for this to work
            rule_name = f"Block_SentinelX_{ip_address}"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip_address}"
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"✅ Successfully blocked {ip_address} via Windows Defender Firewall.")
            return True
            
        else:
            print(f"⚠️ Automatic IP blocking is not configured for OS: {current_os}")
            return False
            
    except subprocess.CalledProcessError:
        print(f"❌ Failed to block {ip_address}. Ensure the script is running with Administrative/Root privileges.")
        return False
    except Exception as e:
        print(f"❌ An error occurred while trying to block {ip_address}: {str(e)}")
        return False

def unblock_ip(ip_address):
    """
    Removes the firewall rule for a previously blocked IP.
    """
    print(f"Unblocking IP: {ip_address}")
    current_os = platform.system().lower()
    
    try:
        if current_os == "linux":
            cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"✅ Successfully unblocked {ip_address} via Linux iptables.")
            return True
            
        elif current_os == "windows":
            rule_name = f"Block_SentinelX_{ip_address}"
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"✅ Successfully removed firewall rule for {ip_address}.")
            return True
            
        return False
    except Exception as e:
        print(f"❌ Failed to unblock {ip_address}: {str(e)}")
        return False

# You can un-comment the below block to safely test it, 
if __name__ == "__main__":
    # block_attacker_ip("192.168.254.254")
    # unblock_ip("192.168.254.254")
    pass
