import joblib
from scapy.all import IP, TCP, sniff

# Load the pre-trained model
model = joblib.load("anomaly_detection_model.pkl")

def extract_features(packet):
    """Extract features from a packet."""
    if IP in packet:
        return [packet[IP].len]  # Example: Use packet size as a feature
    return None

def detect_anomaly(packet):
    """Detect anomalies using the pre-trained model."""
    features = extract_features(packet)
    if features:
        prediction = model.predict([features])
        return prediction == -1  # -1 indicates an anomaly
    return False

# Example usage
def packet_callback(packet):
    if detect_anomaly(packet):
        print(f"Anomaly detected in packet: {packet.summary()}")

# Start sniffing
sniff(offline="/usr/share/metasploit-framework/vendor/bundle/ruby/3.1.0/gems/pcaprub-0.13.1/examples/telnet-raw.pcap", prn=packet_callback)