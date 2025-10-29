import time
from collections import defaultdict

# --- Configuration ---
CHIRP_THRESHOLD = 5     # Max chirps allowed in a short interval
CHIRP_WINDOW_SEC = 10   # Time window for burst detection

# In-memory session tracking: {Source_IP: {'last_time': float, 'count': int}}
SESSION_STATE_TABLE = defaultdict(lambda: {'last_time': 0, 'count': 0})

# --- Simulated CIM/WS-Man Response Templates ---
# In a real tool, this would be SOAP/XML crafted to match the CIM structure.
BENIGN_ERROR_RESPONSE = "CIM_ERR_ACCESS_DENIED: Request timed out."
NULL_RESPONSE = ""
FORWARD_PACKET_SIGNAL = 1
DROP_PACKET_SIGNAL = 0
INJECT_RESPONSE_SIGNAL = 2

def analyze_wsman_request(source_ip, payload_size):
    """
    Simulates the network inspection process for a WS-Man packet.
    Returns an action signal (forward, drop, or inject error).
    """
    current_time = time.time()
    session = SESSION_STATE_TABLE[source_ip]

    # --- Stateful Chirp Detection Logic (Violating SI-4 Thresholds) ---
    
    # Reset count if outside the time window
    if (current_time - session['last_time']) > CHIRP_WINDOW_SEC:
        session['count'] = 0
        session['last_time'] = current_time
        
    session['count'] += 1
    session['last_time'] = current_time

    print(f"[{source_ip}] Chirp Count: {session['count']} in {CHIRP_WINDOW_SEC}s window.")
    
    if session['count'] > CHIRP_THRESHOLD:
        print(f"[DEFENSE ACTION] Burst threshold exceeded. Injecting benign error.")
        
        # Log the incident (AU-6)
        print(f"[AUDIT LOG] Detected C2 burst pattern from {source_ip}. {session['count']} requests/s.")
        
        # Perform Benign Error Injection
        return INJECT_RESPONSE_SIGNAL 
    
    # If not a burst, forward the packet normally for analysis
    return FORWARD_PACKET_SIGNAL

def simulate_packet_processing(requests):
    """Simulates receiving and processing a series of network requests."""
    for req in requests:
        source_ip = req['ip']
        size = req['size']
        
        action = analyze_wsman_request(source_ip, size)

        if action == INJECT_RESPONSE_SIGNAL:
            print(f"--> Injected Response to {source_ip}: '{BENIGN_ERROR_RESPONSE}'")
            # In a live environment, the Python tool would craft and send the TCP/IP RST 
            # or the benign error payload directly back to the source IP.
            # It would then instruct netfilterqueue to drop the original packet to prevent it reaching the host application.
        
        elif action == FORWARD_PACKET_SIGNAL:
            print(f"--> Forwarding Request from {source_ip} to Host Application.")
            
        elif action == DROP_PACKET_SIGNAL:
            print(f"--> Dropping Malicious Packet from {source_ip}.")

# --- Simulated Incoming Requests ---
# Simulating 8 requests over a short period to trigger the defense threshold (CHIRP_THRESHOLD = 5)
simulated_burst = [
    {'ip': '192.168.1.10', 'size': 500}, 
    {'ip': '192.168.1.10', 'size': 500}, 
    {'ip': '192.168.1.10', 'size': 500},
    {'ip': '192.168.1.10', 'size': 500},
    {'ip': '192.168.1.10', 'size': 500}, # Threshold hit here
    {'ip': '192.168.1.10', 'size': 500}, # Defense triggers
    {'ip': '192.168.1.10', 'size': 500},
    {'ip': '192.168.1.10', 'size': 500}
]

# Simulate the scenario
print("--- Starting Python Defender Simulation ---")
simulate_packet_processing(simulated_burst)