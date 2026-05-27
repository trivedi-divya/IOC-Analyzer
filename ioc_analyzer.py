import requests
import csv
import re
import time

API_KEY = "your_virustotal_api_key_here"

def detect_ioc_type(ioc):
    ioc=ioc.strip()
    
    if re.match(r'^[a-fA-F0-9]{32}$',ioc):
        return "hash",ioc
    elif re.match(r'^[a-fA-F0-9]{40}$',ioc):
        return "hash",ioc
    elif re.match(r'^[a-fA-F0-9]{64}$',ioc):
        return "hash",ioc
    elif re.match(r'^https?://',ioc):
        return "url",ioc
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',ioc):
        return "ip",ioc
    else:
        return "domain",ioc
       
def query_virustotal(ioc_type,ioc):
    if ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    elif ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(ioc.encode()).rstrip(b'=').decode()
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    elif ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        return None
        
def parse_results(ioc, ioc_type, data):
    if data is None:
        return {
            "ioc":ioc,
            "type":ioc_type,
            "malicious":"error",
            "suspicious":"error",
            "clean":"error",
            "verdict":"error"
        }
    stats = data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    clean = stats["undetected"]
    
    if malicious > 0:
        verdict = "MALICIOUS"
    elif suspicious > 0:
        verdict = "SUSPECTED"
    else:
        verdict = "CLEAN"
        
    if ioc_type == "ip":
        return {
            "ioc": ioc,
            "type": ioc_type,
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": clean,
            "verdict": verdict,
            "country": data["data"]["attributes"].get("country", "N/A"),
            "asn": data["data"]["attributes"].get("asn", "N/A"),
            "as_owner": data["data"]["attributes"].get("as_owner", "N/A")
        }
    
    elif ioc_type == "hash":
        return {
            "ioc": ioc,
            "type": ioc_type,
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": clean,
            "verdict": verdict,
            "threat_label": data["data"]["attributes"].get("popular_threat_classification", {}).get("suggested_threat_label", "N/A")
        }
        
    elif ioc_type == "domain":
        import datetime
        raw_date = data["data"]["attributes"].get("creation_date", None)
        if raw_date:
            creation_date = datetime.datetime.fromtimestamp(raw_date, datetime.UTC).strftime('%Y-%m-%d')
        else:
            creation_date = "N/A"    
        return {
            "ioc": ioc,
            "type": ioc_type,
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": clean,
            "verdict": verdict,
            "creation_date": creation_date
        }    
           
    else:
        return {
            "ioc": ioc,
            "type": ioc_type,
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": clean,
            "verdict": verdict
        }

def process_csv(input_file, output_file):
    results = []
    
    with open(input_file, "r") as f:
        reader = csv.reader(f)
        next(reader)
        iocs = [row[0] for row in reader]
        
    print(f"\nfound {len(iocs)} IOCs in process....\n")
    
    for ioc in iocs:
        ioc_type, cleaned_ioc = detect_ioc_type(ioc)
        print(f"Checking {ioc_type}: {cleaned_ioc}")
        
        data = query_virustotal(ioc_type, cleaned_ioc)
        result = parse_results(cleaned_ioc, ioc_type, data)
        results.append(result)
        
        print(f"Verdict: {result['verdict']}")
        print("-" * 40)
        
        time.sleep(15)
        
    save_results(results, output_file)
    print(f"\nDone. Results saved to {output_file}")
    
def save_results(results, output_file):
    fieldnames = ["ioc", "type","malicious", "suspicious", 
                  "clean", "verdict", "country", "asn", 
                  "as_owner", "threat_label", "creation_date"]
    
    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
        
process_csv("iocs.csv", "vt_results.csv")
        

        
