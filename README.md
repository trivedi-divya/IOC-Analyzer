# IOC Analyzer

A Python-based threat intelligence tool that automates IOC (Indicator of Compromise) 
analysis using the VirusTotal API. Built to support DFIR workflows by enabling 
fast, structured enrichment of multiple IOCs in bulk.

## Overview

During incident response investigations, analysts often need to quickly assess 
whether IPs, domains, URLs, or file hashes are malicious. This tool automates 
that process by querying VirusTotal for each IOC and generating a structured 
CSV report with verdicts and contextual information.

## Features

- Supports multiple IOC types like MD5, SHA1, SHA256 hashes, IP addresses, domains, and URLs
- Auto-detects IOC type from input so no manual categorization needed
- Queries VirusTotal API for each IOC
- Generates structured CSV report with verdict, threat labels, and geo-information
- Handles rate limiting automatically with built-in delay between requests

## Requirements

- Python 3.x
- requests library
- VirusTotal API key (free tier works)

## Installation

1. Clone this repository
**git clone https://github.com/yourusername/ioc-analyzer.git**

2. Install dependencies
**pip install requests**

3. Add your VirusTotal API key in the script
**API_KEY = "your_virustotal_api_key_here"**

## Usage

1. Prepare a CSV file named iocs.csv with a header row

Example:

| ioc |
|-------|
|8.8.8.8|
|google.com|
|44d88612fea8a8f36de82e1278abb02f|

3. Run the script
**python ioc_analyzer.py**

4. Results will be saved to vt_results.csv

## Output Fields

| Field | Description |
|-------|-------------|
| IOC | The original indicator |
| Type | Hash / IP / Domain / URL |
| Malicious | Number of malicious detections |
| Suspicious | Number of suspicious detections |
| Clean | Number of clean detections |
| Verdict | MALICIOUS / SUSPECTED / CLEAN |
| Country | Country of origin (IPs only) |
| ASN | Autonomous System Number (IPs only) |
| AS Owner | Network owner (IPs only) |
| Threat Label | Malware family or type (hashes only) |
| Creation Date | Domain registration date (domains only) |

## Use Case

This tool was built to support real-world incident response workflows where 
analysts need to triage large numbers of IOCs quickly during active investigations.

## Author

Divya Trivedi

DFIR Analyst | Digital Forensics | Incident Response

https://www.linkedin.com/in/trivedi-divya/

https://medium.com/@dgtrivedi4646/
