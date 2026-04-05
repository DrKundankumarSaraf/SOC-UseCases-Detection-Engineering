# SOC-UseCases-Detection-Engineering
Real-world SOC detection use cases mapped with MITRE ATT&amp;CK using Splunk &amp; Microsoft Sentinel (KQL)
# SOC Use Cases & Detection Engineering

This repository contains real-world SOC detection use cases, mapped with MITRE ATT&CK techniques and implemented using SIEM tools like Splunk and Microsoft Sentinel.

## 🔍 Covered Use Cases

1. Brute Force Attack Detection
2. Privilege Escalation Detection
3. Suspicious PowerShell Activity
4. Data Exfiltration Detection
5. Malware Execution Indicators

## 🛠 Tools
- Splunk
- Microsoft Sentinel (KQL)
- MITRE ATT&CK Framework

## 📊 Sample Detection (KQL)

```kql
SigninLogs
| where ResultType == "50053"
| summarize count() by IPAddress
| where count_ > 10
