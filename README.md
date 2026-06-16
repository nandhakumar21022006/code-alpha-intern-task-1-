**🔒 Cyber Security Internship – Task 1**
Network Traffic Analysis & Packet Sniffing using Python (Kali Linux)
This repository contains the work completed for Task 1 of the Cyber Security Internship. The objective of this task is to capture and analyze network traffic packets, understand packet structures, and observe how data flows across a network using Python and Kali Linux.

**📌 Task Objective**
To build a Python-based network packet sniffer capable of:
Capturing live network traffic
Identifying source and destination IP addresses
Detecting network protocols
Analyzing packet structures
Understanding communication flow between devices

**🛠 Tools Used**
Kali Linux
Used as the primary operating system for network monitoring and packet analysis.
Python 3
Used to develop the packet sniffer application.
Socket Library
Used to capture and process raw network packets.
Wireshark (Optional)
Can be used to verify captured traffic and analyze packet exchanges visually.

**🚀 Steps Performed**
Built a Packet Sniffer
Developed a Python program using raw sockets to capture network packets directly from the network interface.
Captured Live Network Traffic
Executed the packet sniffer and generated network traffic using ICMP ping requests.
**Example:**
ping google.com
Analyzed Packet Structure
Extracted and displayed:
Source IP Address
Destination IP Address
MAC Addresses
Protocol Type
Packet Length
IPv4 Header Information
Generated Traffic Statistics
Displayed:
Total Packets Captured
Total Bytes Captured
Protocol Distribution
Top Source Addresses
Saved Capture Results
Output was recorded in:
task1_capture.log

**🔍 Key Findings**
✔ Successfully captured 100 network packets

✔ Identified ICMP Echo Requests and Echo Replies

✔ Displayed source and destination IP addresses

✔ Observed packet flow between the local machine and external hosts

✔ Generated protocol statistics and traffic summaries

**Example Communication:**
10.0.2.15  →  142.250.143.113
ICMP Echo Request

142.250.143.113  →  10.0.2.15
ICMP Echo Reply

**📚 Key Concepts Learned**
✔ Packet Sniffing
Capturing and inspecting network packets as they travel across a network.
✔ Network Protocol Analysis
Understanding how protocols such as ICMP, TCP, and UDP operate.
✔ IP Address Identification
Determining packet origin and destination through source and destination IP fields.
✔ Network Traffic Monitoring
Observing real-time communication occurring on a network.
✔ Packet Structure Analysis
Understanding Ethernet frames, IP headers, and protocol-specific information.

**📊 Results**
Capture Summary:
Total Packets Captured : 100
Total Bytes Captured   : 9,860

Protocol Distribution:
ICMP    : 98
PROTO0  : 2

**✅ Conclusion**
This task provided practical experience in packet sniffing, network traffic analysis, and protocol inspection using Python and Kali Linux. The developed packet sniffer successfully captured live network traffic, analyzed packet details, and demonstrated how devices communicate across a network. This task strengthens foundational knowledge in network security and cybersecurity monitoring.
