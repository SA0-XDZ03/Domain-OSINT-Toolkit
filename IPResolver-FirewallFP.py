#ADD HEADERS WORDLIST
#ADD FIREWALL INFO WORDLIST

import socket
import requests

def detect_firewall(ip_address):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
    response = requests.get(f"http://{ip_address}", headers=headers, timeout=5)
    
    firewall_info = {
        "Cloudflare": {"headers": ["CF-RAY", "Server"], "type": "Reverse Proxy"},
        "Incapsula": {"headers": ["X-Iinfo", "X-CDN"], "type": "Reverse Proxy"},
        # Add more firewall types here
    }
    
    detected_firewalls = []
    
    for firewall, info in firewall_info.items():
        firewall_detected = True
        for header in info["headers"]:
            if header not in response.headers:
                firewall_detected = False
                break
        if firewall_detected:
            detected_firewalls.append({"name": firewall, "type": info["type"]})
    
    return detected_firewalls

def resolve_domain_to_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        return str(e)

if __name__ == "__main__":
    domain = input("Enter a domain name: ")
    ip_address = resolve_domain_to_ip(domain)
    
    if ip_address:
        print(f"IP address of {domain}: {ip_address}")
        
        detected_firewalls = detect_firewall(ip_address)
        
        if detected_firewalls:
            print("Detected Firewalls:")
            for firewall in detected_firewalls:
                print(f"- Name: {firewall['name']}, Type: {firewall['type']}")
        else:
            print("No known firewalls detected.")
    else:
        print("Failed to resolve domain to IP address")
