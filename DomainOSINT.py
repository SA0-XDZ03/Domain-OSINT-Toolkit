import requests
import socket
import certifi
import ssl
import dns.resolver
from bs4 import BeautifulSoup

def getIPInfo(URL): # NEED TO WORK ON
    try:
        ipAddress = socket.gethostbyname(URL)
        response = requests.get(f"https://ipinfo.io/{ipAddress}/json")
        ipData = response.json()

        return {
            "URL": URL,
            "IP Address": ipAddress,
            "Location": f"{ipData.get('city', '')}, {ipData.get('region', '')}, {ipData.get('country', '')}",
            "ISP": ipData.get('org', '')
        }
    except (socket.gaierror, requests.exceptions.RequestException):
        return "Invalid URL or Unable to resolve IP information."

def SSLInfo(URL): # NEED TO WORK ON
    try:
        sslInfo = requests.get(f"https://api.ssllabs.com/api/v3/analyze?host={URL}")
        sslData = sslInfo.json()
        return sslData
    except requests.exceptions.RequestException:
        return "Unable to fetch SSL information."

def httpHeaders(URL): # NEED TO WORK ON
    try:
        headersHTTP = requests.get(f"https://{URL}")
        headersHTTPData = headersHTTP.headers
        return headersHTTPData
    except requests.exceptions.RequestException:
        return "Unable to fetch HTTP headers."

def whoisINFO(URL): # NEED TO WORK ON
    try:
        whoisInfo = requests.get(f"https://www.whois.com/whois/{URL}")
        whoisInfoData = whoisInfo.text
        return whoisInfoData
    except Exception as exception:
        return "Unable to fetch Whois Information."

def technologyStack(URL): # NOT WORKING
    try:
        serverHeader = headers.get('Server')
        print(serverHeader)
        return serverHeader
    except Exception as exception:
        return "Unable to fetch TechStack Information."

# def getSSLCertificateChain(URL): # NOT WORKING
#     try:
#         response = requests.get(f"https://{URL}", verify=certifi.where())
#         certificates = response.request._certificate
#         return certificates
#     except requests.exceptions.RequestException:
#         return "Unable to fetch SSL certificate chain."

def getDNSRecords(URL): # NEED TO WORK ON
    try:
        answers = dns.resolver.resolve(URL)
        dns_records = {}
        for rdata in answers:
            dns_records[rdata.rdtype] = rdata.to_text()
        return dns_records
    except dns.resolver.NXDOMAIN:
        return "Domain does not exist."
    except dns.exception.DNSException:
        return "Error retrieving DNS records."

def getHSTSInfo(URL):
    try:
        headersHTTP = requests.get(f"https://{URL}").headers
        hsts_value = headersHTTP.get('Strict-Transport-Security', 'Not found')
        return hsts_value
    except requests.exceptions.RequestException:
        return "Unable to fetch HSTS information."

def checkMalwarePhishing(URL):
    None
    # You can use a third-party API/service to check for malware and phishing status.
    # An example is Google Safe Browsing API.
    # Implement this function accordingly.

def getDomainsAndSubdomains(URL):
    try:
        answers = dns.resolver.resolve(URL, 'CNAME')
        domains = set()
        for rdata in answers:
            domain = rdata.target.to_text()
            domains.add(domain)
        return domains
    except dns.exception.DNSException:
        return "Error retrieving domains/subdomains."

def getLinkedAndListedPages(URL):
    try:
        response = requests.get(f"https://{URL}")
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('http'):
                links.add(href)
        return list(links)
    except requests.exceptions.RequestException:
        return "Error retrieving linked/listed pages."

if __name__ == "__main__":
    inputURL = input("Enter URL: ")
    
    ipResult = getIPInfo(inputURL)
    sslResult = SSLInfo(inputURL)
    httpHeadersResult = httpHeaders(inputURL)
    whoisInfoResult = whoisINFO(inputURL)
    technologyStackResult = technologyStack(inputURL)
#    sslCertificateChainResult = getSSLCertificateChain(inputURL)
    dnsRecordsResult = getDNSRecords(inputURL)
    hstsInfo = getHSTSInfo(inputURL)
    malwarePhishingResult = checkMalwarePhishing(inputURL)
    domainsSubdomains = getDomainsAndSubdomains(inputURL)
    linkedListedPages = getLinkedAndListedPages(inputURL)

    print("\n=================================================")
    print("IP Information:")
    if isinstance(ipResult, dict):
        for key, value in ipResult.items():
            print(f"{key}: {value}")
    else:
        print(ipResult)
    print("\n=================================================")
    print("SSL Information:")
    if isinstance(sslResult, dict):
        for key, value in sslResult.items():
            print(f"{key}: {value}")
    else:
        print(sslResult)
    print("\n=================================================")
    print("HTTP Headers:")
    if isinstance(httpHeadersResult, dict):
        for key, value in httpHeadersResult.items():
            print(f"{key}: {value}")
    else:
        print(httpHeadersResult)
    print("\n=================================================")
    print("Whois Information: ")
    if isinstance(whoisInfoResult, dict):
        for key, value in whoisInfoResult.items():
            print(f"{key}: {value}")
    else:
        print(whoisInfoResult)
    print("\n=================================================")
    print("Technology Stack Information: ")
    if isinstance(technologyStackResult, dict):
        for key, value in technologyStackResult.items():
            print(f"{key}: {value}")
    else:
        print(technologyStackResult)
    # print("\n=================================================")
    # print("SSL Chain Certificate Information")
    # if isinstance(sslCertificateChainResult, dict):
    #     for key, value in sslCertificateChainResult.items():
    #         print(f"{key}: {value}")
    # else:
    #     print(sslCertificateChainResult)
    print("\n=================================================")
    print("DNS Records:")
    if isinstance(dnsRecordsResult, dict):
        for key, value in dnsRecordsResult.items():
            print(f"{key}: {value}")
    else:
        print(dnsRecordsResult)
    print("\n=================================================")
    print("HSTS Information:")
    print(hstsInfo)

    print("\n=================================================")
    print("Malware/Phishing Status:")
    print(malwarePhishingResult)

    print("\n=================================================")
    print("Domains and Subdomains:")
    if isinstance(domainsSubdomains, set):
        for domain in domainsSubdomains:
            print(f"Domain/Subdomain: {domain}")

    print("\n=================================================")
    print("Linked Pages and Listed Pages:")
    if isinstance(linkedListedPages, list):
        for page in linkedListedPages:
            print(f"Page: {page}")