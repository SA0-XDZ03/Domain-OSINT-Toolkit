# VERY UNSTABLE
import re
import urllib3
import requests
import logging
import subprocess

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

def main():
    domainSearchKeyword = input("Enter Keywords: ")
    domainIntelligence(domainSearchKeyword)

def domainIntelligence(domainSearchKeyword):
    domainEnum(domainSearchKeyword)
#    domainGitHubTools(domainSearchKeyword)
#    domainSubDirectoryFuzzer()
#    domainToGoogleDork()
#    domainToSearchEngine()
#    domainToWHOIS()
#    domainToDNSInfo()
#    domainToJuicyFiles()
#    domainToIPReputation()
#    domainToSecurityHeaders()
#    domainToWhatWeb()
#    HTTPProxySetup()
#    domainVulnScan()
#    domainSourceCodeScan()
#    domainOSINT()
#    domainComplianceChecks()

def checkHTTPStatus(validURL):
    try:
        response = requests.get(validURL)
        return response.status_code
    except requests.exceptions.RequestException:
        return None

def domainEnum(searchDomainKeyword):
    generalTLDs = []
    geoTLDs = []
    generalSubDomains = []
    fuzzedDomains = []
    UniqueSortedDomains = set()
    ActiveDomains = set()
    
    with open("./Resources/Samples/SSUBD.txt", "r", encoding="utf-8") as SubDomainFile:
        for SubDomain in SubDomainFile:
            generalSubDomains.append(SubDomain.strip())
            
    with open("./Resources/Samples/SGTLDS.txt", "r", encoding="utf-8") as TLDFile:
        for TLD in TLDFile:
            generalTLDs.append(TLD.strip())
            
    with open("./Resources/Samples/SGEOTLDS.txt", "r", encoding="utf-8") as GTLDFile:
        for GTLD in GTLDFile:
            geoTLDs.append(GTLD.strip())

    for topDomains in generalTLDs:
        if topDomains and topDomains != ".":
            #domainOneHTTP = "http://" + searchDomainKeyword + "." + topDomains
            domainOneHTTPS = "https://" + searchDomainKeyword + "." + topDomains
    
    for geoDomains in geoTLDs:
        if geoDomains and geoDomains != ".":
            #domainSevenHTTP = "http://" + searchDomainKeyword + "." + geoDomains
            domainSevenHTTPS = "https://" + searchDomainKeyword + "." + geoDomains
    
    for topDomains in generalTLDs:
        for geoDomains in geoTLDs:
            if topDomains and topDomains != ".":
                if geoDomains and geoDomains != ".":
                    domainTwoHTTPS = "https://" + searchDomainKeyword + "." + topDomains + "." + geoDomains
                    domainThreeHTTPS = "https://" + searchDomainKeyword + "." + geoDomains + "." + topDomains
                    #domainTwoHTTP = "http://" + searchDomainKeyword + "." + topDomains + "." + geoDomains
                    #domainThreeHTTP = "http://" + searchDomainKeyword + "." + geoDomains + "." + topDomains

    for topDomains in generalTLDs:
        for geoDomains in geoTLDs:
            for subDomain in generalSubDomains:
                if topDomains and topDomains != ".":
                    if geoDomains and geoDomains != ".":
                        if subDomain and subDomain != ".":
                            #domainFourHTTP = "http://" + subDomain + "." + searchDomainKeyword + "." + topDomains
                            #domainFiveHTTP = "http://" + subDomain + "." + searchDomainKeyword + "." + topDomains + "." + geoDomains
                            #domainSixHTTP = "http://" + subDomain + "." + searchDomainKeyword + "." + geoDomains + "." + topDomains
                            domainFourHTTPS = "https://" + subDomain + "." + searchDomainKeyword + "." + topDomains
                            domainFiveHTTPS = "https://" + subDomain + "." + searchDomainKeyword + "." + topDomains + "." + geoDomains
                            domainSixHTTPS = "https://" + subDomain + "." + searchDomainKeyword + "." + geoDomains + "." + topDomains
                            #fuzzedDomains += [domainOneHTTP, domainTwoHTTP, domainThreeHTTP, domainFourHTTP, domainFiveHTTP, domainSixHTTP, domainOneHTTPS, domainTwoHTTPS, domainThreeHTTPS, domainFourHTTPS, domainFiveHTTPS, domainSixHTTPS]
                            fuzzedDomains += [domainOneHTTPS, domainTwoHTTPS, domainThreeHTTPS, domainFourHTTPS, domainFiveHTTPS, domainSixHTTPS, domainSevenHTTPS]
    
    with open("./Resources/Samples/Logs/FuzzedDomains.txt","w") as AllDomainsFile:
        fuzzedDomains.sort()
        for domains in fuzzedDomains:
            AllDomainsFile.write(domains + "\n")
    
    with open("./Resources/Samples/Logs/FuzzedDomains.txt","r") as AllDomainsFile:
        for domainsAll in AllDomainsFile:
            validURL = domainsAll.strip()
            UniqueSortedDomains.add(validURL)
    
    with open("./Resources/Samples/Logs/UniqueSortedDomains.txt", "w") as UniqueDomainsFile:
        for domainsUnique in sorted(UniqueSortedDomains):
            UniqueDomainsFile.write(domainsUnique + "\n")
    
    with open("./Resources/Samples/Logs/UniqueSortedDomains.txt","r") as UniqueDomainsFile:
        for domainsUnique in sorted(UniqueSortedDomains):
            httpStatus = checkHTTPStatus(domainsUnique)
            if httpStatus is not None and httpStatus < 400:
                ActiveDomains.add(domainsUnique)
    
    with open("./Resources/Samples/Logs/ActiveDomains.txt", "w") as ActiveDomainsFile:
        for domainsActive in sorted(ActiveDomains):
            ActiveDomainsFile.write(domainsActive + "\n")

    with open("./Resources/Samples/Logs/ActiveDomains.txt", "r") as ActiveDomainsFile:
        for domainActive in ActiveDomains:
            print(domainActive)
    
def domainGitHubTools():
    pass

if __name__ == "__main__":
    main()

