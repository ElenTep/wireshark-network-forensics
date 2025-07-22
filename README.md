# wireshark-network-forensics
This project simulates a real-world cybersecurity investigation using Wireshark to analyze a PCAP file from a simulated network breach. Acting as a Tier 1–2 SOC Analyst, I identified Indicators of Compromise (IOCs), attacker behavior, and possible lateral movement across a corporate LAN environment.

# 🕵️ Wireshark Network Forensics: Detecting C2 and Lateral Movement in Simulated Breach Scenario

## Overview
This project simulates a real-world network forensics investigation. Using Wireshark, I analyzed a PCAP file from a simulated security breach to identify suspicious behavior, indicators of compromise (IOCs), and possible lateral movement. This exercise demonstrates Tier 1–2 SOC Analyst workflows for analyzing network activity and reporting findings.
This GitHub project presents a network forensic investigation using Wireshark, simulating a real-world breach scenario.

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

## Deliverables
- 📄 `Incident Analysis Report.pdf`  [Incident Analysis Report.pdf](https://github.com/user-attachments/files/21376578/Incident.Analysis.Report.pdf)
- 🖼️ Annotated screenshots in `/evidence/`  
- 🧠 `IOCs_summary.txt` 

- 📝 Timeline and findings in Markdown  

## Folder Structure
![Beaconing Pattern](evidence/beaconing-pattern.png)

├── dns-queries.png
├── beaconing-pattern.png
├── c2-http-traffic.png
├── smb-lateral.png

IOCs_summary.txt
Investigation_Report.pdf


## Tools Used
- Wireshark  
- Markdown  
- MITRE ATT&CK Navigator  
- Screenshot annotation tools  

## Author
**Elena Teplyakova**  
Cybersecurity Analyst | CompTIA CySA+, A+ | Splunk Core Certified
[Connect with me on LinkedIn](https://www.linkedin.com/in/elena-tepliakova-732a662a5/)
