# wireshark-network-forensics
This project simulates a real-world cybersecurity investigation using Wireshark to analyze a PCAP file from a simulated network breach. Acting as a Tier 1–2 SOC Analyst, I identified Indicators of Compromise (IOCs), attacker behavior, and possible lateral movement across a corporate LAN environment.

# 🕵️ Wireshark Network Forensics: Detecting C2 and Lateral Movement in Simulated Breach Scenario

## Overview
This project simulates a real-world network forensics investigation. Using Wireshark, I analyzed a PCAP file from a simulated security breach to identify suspicious behavior, indicators of compromise (IOCs), and possible lateral movement. This exercise demonstrates Tier 1–2 SOC Analyst workflows for analyzing network activity and reporting findings.
This GitHub project presents a network forensic investigation using Wireshark, simulating a real-world breach scenario.

## Table of Contents
- [Overview](#overview)
- [Objectives](#objectives)
- [Environment Details](#environment-details)
- [MITRE ATT&CK Techniques Observed](#mitre-attck-techniques-observed)
- [Deliverables](#deliverables)
- [Folder Structure](#folder-structure)
- [Tools Used](#tools-used)
- [Author](#author)

## Objectives
- ✅ Detect beaconing, C2 communications, and suspicious DNS/HTTP activity  
- ✅ Identify compromised host and user  
- ✅ Analyze lateral movement (e.g., SMB/RDP)  
- ✅ Map activity to MITRE ATT&CK techniques (T1071, T1043, T1021)  
- ✅ Document investigation flow and IOCs  

## Environment Details
- **LAN Segment:** `10.6.13.0/24`  
- **Domain:** `massfriction[.]com`  
- **Domain Controller:** `10.6.13.3 (WIN-DQL4WFWJXQ4)`  
- **Infected Host:** `10.6.13.133 (DESKTOP-5AVE44C)`  

## MITRE ATT&CK Techniques Observed 
| Technique ID | Name                                      | Description                   |
|--------------|-------------------------------------------|-------------------------------|
| T1071.001    | Application Layer Protocol: Web Protocols | C2 over HTTP                  |
| T1043        | Commonly Used Port                        | Suspicious outbound traffic   |
| T1021.002    | Remote Services: SMB                      | Lateral movement via SMB      |

## Folder Structure

- 🖼️ `/evidence/` — contains key annotated screenshots:
  - `dns-queries.png` <img width="1341" height="800" alt="dns-queries" src="https://github.com/user-attachments/assets/d677ab02-363e-4ef1-a661-24ff3f695a2c" />
  - `beaconing-pattern.png` <img width="1261" height="879" alt="beaconing-pattern" src="https://github.com/user-attachments/assets/737d2ada-3234-4828-a46f-0cedd8b52a5b" />
  - `c2-http-traffic.png` <img width="1282" height="818" alt="c2-http-traffic" src="https://github.com/user-attachments/assets/bdf9b55e-f6b5-4956-85c4-600cbfedfd32" />
  - `smb-lateral.png` <img width="1290" height="797" alt="SMB Lateral Movement Attempt" src="https://github.com/user-attachments/assets/b05c47ae-c2f2-4e6c-b015-a7dc09f08bc4" />
      
- 📄 `Wireshark_Investigation_Report.pdf`[Wireshark_Investigation_Report.pdf](https://github.com/user-attachments/files/21391004/Wireshark_Investigation_Report.pdf)

### 🔍 Key Evidence

**1. DNS Requests (Suspicious Queries)**
![DNS Queries] <img width="1341" height="800" alt="dns-queries" src="https://github.com/user-attachments/assets/d677ab02-363e-4ef1-a661-24ff3f695a2c" />

**2. Beaconing Pattern (Regular Intervals)**
![Beaconing Pattern](evidence/beaconing-pattern.png)

**3. HTTP POST with System Info (C2)**
![C2 Communication](evidence/c2-http-traffic.png)

**4. SMB Lateral Movement Attempt**
![SMB Lateral](evidence/smb-lateral.png)


## 🔎 Summary of Key Findings

- Infected host: `10.6.13.133 (DESKTOP-5AVE44C)`
- C2 traffic over HTTP to suspicious domain `hillcoweb.com`
- Repeated DNS beaconing to remote servers
- Possible data exfiltration via PowerShell POST request
- Lateral movement signs using SMB (10.6.13.133 → 10.6.13.5)

## 🧪 Investigation Flow

1. Opened PCAP in Wireshark
2. Filtered for suspicious DNS (`dns.qry.name contains ".com"`)
3. Identified beaconing using `ip.addr == 10.6.13.133` and `http.request`
4. Followed TCP streams for POST requests
5. Noted internal SMB connection (10.6.13.5), suspecting lateral movement
6. Mapped TTPs to MITRE ATT&CK
7. Documented IOCs

## Tools Used
- Wireshark  
- Markdown  
- MITRE ATT&CK Navigator  
- Screenshot annotation tools
  

## Author
**Elena Teplyakova**  
Cybersecurity Analyst | CompTIA CySA+, A+ | Splunk Core Certified
[Connect with me on LinkedIn](https://www.linkedin.com/in/elena-tepliakova-732a662a5/)
