# CIC-IDS2017 Network Intrusion Detection Dataset

## About Dataset

This project uses the **CIC-IDS2017 Intrusion Detection Evaluation Dataset**, a widely used cybersecurity dataset designed for developing and evaluating **Network Intrusion Detection Systems (IDS)**.

The dataset contains **realistic network traffic captured in a controlled environment**, including both **normal user behavior** and **multiple types of cyber attacks**.

Because the dataset size is approximately **800 MB**, it cannot be included directly in this GitHub repository.

Please download the dataset from the following source and extract it inside this `Dataset/` folder.

Dataset Download Link:

https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset

After downloading, extract all CSV files into this directory.

Expected folder structure:
Dataset/
README.md
Monday-WorkingHours.pcap_ISCX.csv
Tuesday-WorkingHours.pcap_ISCX.csv
Wednesday-workingHours.pcap_ISCX.csv
Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
Friday-WorkingHours-Morning.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-DDoS.pcap_ISCX.csv


---

# Dataset Overview

The dataset contains **network flow statistics extracted from packet captures (PCAP files)** using flow analysis tools.

Each row in the dataset represents a **network traffic flow**, summarized using **79 statistical features** describing packet size, timing, flags, and other network characteristics.

These features are used to detect abnormal or malicious network behavior.

---

# Classes in Dataset

The dataset contains two general categories:

- **BENIGN** (Normal network activity)
- **ANOMALY / ATTACK**

Attack types included in the dataset:

| Attack Type | Description |
|-------------|-------------|
| DoS Hulk | High volume Denial-of-Service attack |
| DDoS | Distributed Denial-of-Service |
| PortScan | Scanning network ports |
| FTP-Patator | FTP brute force attack |
| SSH-Patator | SSH brute force attack |
| Slowloris | Slow HTTP DoS attack |
| SlowHTTPTest | Slow HTTP testing attack |
| GoldenEye | DoS attack targeting web servers |
| Web Attack - Brute Force | Password brute force |
| Web Attack - XSS | Cross-Site Scripting attack |
| Web Attack - SQL Injection | SQL Injection attack |
| Botnet | Malware botnet communication |
| Infiltration | Malware infiltration |
| Heartbleed | OpenSSL vulnerability exploit |

---

# Features of Dataset

Each traffic flow contains **79 extracted features**, including:

### Network Information
- Destination Port
- Flow Duration
- Total Forward Packets
- Total Backward Packets

### Packet Statistics
- Packet Length Mean
- Packet Length Standard Deviation
- Max Packet Length
- Min Packet Length

### Traffic Rate Features
- Flow Bytes per second
- Flow Packets per second
- Forward Packets per second
- Backward Packets per second

### Timing Features
- Flow IAT Mean
- Flow IAT Standard Deviation
- Active Time
- Idle Time

### TCP Flag Features
- SYN Flag Count
- ACK Flag Count
- RST Flag Count
- FIN Flag Count
- PSH Flag Count
- URG Flag Count

These statistical features help machine learning models identify patterns associated with malicious behavior.

---

# Attack Scenarios in Dataset

## Monday, July 3, 2017
Normal network traffic (Benign human activity).

---

## Tuesday, July 4, 2017
### Brute Force Attacks

FTP-Patator  
09:20 – 10:20

SSH-Patator  
14:00 – 15:00

Attacker System  
Kali Linux — 205.174.165.73

Victim System  
Web Server (Ubuntu) — 205.174.165.68  
Local IP — 192.168.10.50

---

## Wednesday, July 5, 2017
### DoS and DDoS Attacks

- DoS Slowloris (09:47 – 10:10)
- DoS SlowHTTPTest (10:14 – 10:35)
- DoS Hulk (10:43 – 11:00)
- DoS GoldenEye (11:10 – 11:23)

### Heartbleed Attack
15:12 – 15:32

---

## Thursday, July 6, 2017

### Web Attacks (Morning)

- Web Attack – Brute Force (09:20 – 10:00)
- Web Attack – XSS (10:15 – 10:35)
- Web Attack – SQL Injection (10:40 – 10:42)

### Infiltration Attacks (Afternoon)

- Dropbox download infiltration
- Metasploit Windows Vista exploit
- MAC infiltration

---

## Friday, July 7, 2017

### Botnet Activity
ARES Botnet  
10:02 – 11:02

### Port Scan Attacks
Multiple scanning techniques including:

- SYN Scan
- TCP Scan
- FIN Scan
- XMAS Scan
- NULL Scan

### DDoS Attack
LOIT Attack  
15:56 – 16:16

---

# Possible Research Tasks

This dataset can be used for several machine learning experiments:

1. Detect network anomalies using supervised learning.
2. Identify patterns in normal vs malicious traffic.
3. Apply unsupervised learning methods for anomaly detection.
4. Develop behavioral models for abnormal network activity detection.

---

# Model Evaluation Metrics

Recommended metrics for validating models:

- Accuracy
- Precision (Micro / Macro / Weighted)
- Recall
- Sensitivity
- F1 Score
- ROC Curve
- AUC Score
- Classification Report
- Custom evaluation metrics

Researchers should justify why a particular metric is used for evaluation.

---

# Important Notes

The dataset is large (~800 MB) and therefore cannot be stored directly in this repository.

Please download it from Kaggle and extract the files into this folder before running any preprocessing or training scripts.

---

# Disclaimer

This dataset is **not owned by the author of this repository**.

It is provided for **educational and research purposes only**.

If you are the owner of this dataset and would like it removed or modified, please contact the repository owner.

For more information about the dataset, visit:

https://www.unb.ca/cic/datasets/ids-2017.html