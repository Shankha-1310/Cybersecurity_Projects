# Cybersecurity Projects

A collection of Python-based security tools built to understand and replicate real Tier-1 SOC workflows: packet analysis, port scanning, and classical cryptography — plus a phishing-awareness deck.

## Projects

### Network Sniffer (`network_sniffer.py`)
Captures and parses live TCP/IP traffic across multiple protocols. Inspects headers, source/destination IPs, and payloads to flag anomalous connections and protocol misuse — the same triage pattern used in Tier-1 SOC alert queues.

**Run it:**
```bash
sudo python3 network_sniffer.py
```
*(Requires root/admin privileges to open a raw socket. Tested on Kali Linux.)*

### NMapper (`nmapper.py`)
Scans a target IP or range and classifies ports as open, closed, or filtered across TCP/UDP. Maps findings against known service baselines to highlight unauthorized exposure — a lightweight, from-scratch alternative to Nmap for understanding how port scanning actually works under the hood.

**Run it:**
```bash
python3 nmapper.py <target-ip>
```

### Caesar Cipher (`caesar_cipher.py`)
A configurable shift-based encryption/decryption tool. Built to demonstrate why classical ciphers are cryptographically weak by modern standards, and to reinforce fundamentals before working with real cryptographic libraries.

**Run it:**
```bash
python3 caesar_cipher.py
```

### Phishing Attacks: Recognizing and Avoiding the Threat
A presentation (`Phishing-Attacks-Recognizing-and-Avoiding-the-Threat.pptx`) covering common phishing tactics, red flags, and prevention strategies.

## Tech Stack
- Python 3
- `socket`, `struct` (raw packet parsing)
- Kali Linux / Fedora Linux

## Disclaimer
These tools are for educational use and authorized testing only. Do not run the sniffer or scanner against networks or hosts you don't own or have explicit permission to test.

## Author
**Shankha Das** — [LinkedIn](https://linkedin.com/in/shankha-das) · [GitHub](https://github.com/Shankha-1310)
