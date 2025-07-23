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
  - `dns-queries.png`
  - `beaconing-pattern.png`
  - `c2-http-traffic.png`
  - `smb-lateral.png`

- 📝 `IOCs_summary.txt` — Indicators of Compromise
- 📄 `Wireshark_Investigation_Report.pdf`[Wireshark_Investigation_Report.pdf](https://github.com/user-attachments/files/21390273/Wireshark_Investigation_Report.pdf)
 — Full analysis report


## Tools Used
- Wireshark  
- Markdown  
- MITRE ATT&CK Navigator  
- Screenshot annotation tools  

## Author
**Elena Teplyakova**  
Cybersecurity Analyst | CompTIA CySA+, A+ | Splunk Core Certified
[Connect with me on LinkedIn](https://www.linkedin.com/in/elena-tepliakova-732a662a5/)
