# IOC Analyzer


A Python tool that automates IOC (Indicator of Compromise) enrichment using the VirusTotal API.

## What it does
- Accepts a CSV file containing IOCs (hashes, IPs, domains, and URLs)
- Automatically detects the IOC type
- Queries VirusTotal for each IOC
- Outputs structured results including verdict, threat labels, and geo-information to a CSV report

## Requirements
- Python 3.x
- requests library

## Setup
1. Clone this repository
2. Install dependencies: **pip install requests**
3. Add your VirusTotal API key in the script where it says **your_virustotal_api_key_here**
4. Add your IOCs in a CSV file named **iocs.csv** with a header row
5. Run: **python ioc_analyzer.py**

## Output
Results are saved to vt_results.csv with the following fields:
IOC, Type, Malicious, Suspicious, Clean, Verdict, Country, ASN, Threat Label, Creation Date

## Author
Divya Trivedi — DFIR Analyst
