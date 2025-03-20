import requests

def check_ip_reputation(ip):
    """Check the reputation of an IP using VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": "eb7f8ebff6ec2a98a9e478ab8e0907c8ca08b2986bd0948e7a958c920f8f335e"}  # Replace with your API key
    response = requests.get(url, headers=headers)
    return response.json()

# Example usage
ip_reputation = check_ip_reputation("8.8.8.8")  # Replace with the IP you want to check
print(ip_reputation)