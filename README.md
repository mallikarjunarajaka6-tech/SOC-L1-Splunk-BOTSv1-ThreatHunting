# SOC L1 Threat Hunting Lab – BOTSv1 Splunk

## Project Overview
Built a SOC L1 Threat Hunting Lab using Splunk Enterprise with BOTSv1 attack-only dataset. Focused on detecting T1110 Brute Force, T1078 Valid Accounts, and validating T1003 Credential Dumping. Key achievement: Troubleshot non-standard log schema and documented production remediation.

## Skills Demonstrated
Splunk SPL, MITRE ATT&CK T1110/T1078/T1003, Log Analysis, Data Troubleshooting, True Negative Documentation, Detection Engineering, SOC L1 Workflow

## Key Findings
1. **T1110 Brute Force**: 28 failed logons EventCode 4625 detected
2. **T1078 Valid Accounts**: 6,464 successful logons EventCode 4624 validated  
3. **Schema Challenge**: Standard `stats by user` returned 0 rows due to URL-encoded proxy logs
4. **True Negative**: T1003 Mimikatz hunt returned 0 results, proving detection coverage validation
5. **Remediation**: Documented `rex` field extraction for production alerting

## Proof of Concept – SOC L1 Threat Hunting Lab

### Objective
Demonstrate end-to-end SOC L1 workflow: detect T1110 Brute Force, troubleshoot non-standard log schema, validate true negatives, and document production remediation. Dataset: BOTSv1 attack-only.

### Environment
- **Tool**: Splunk Enterprise 9.x Free Trial
- **Dataset**: BOTSv1, `index=botsv1`
- **Time Range**: All Time
- **MITRE Techniques**: T1110 Credential Access, T1078 Defense Evasion, T1003 Credential Dumping

### POC Steps – Reproducible

#### Step 1: Detect T1110 Brute Force Activity
```spl
index=botsv1 sourcetype=botsv1 4625
| stats count as failed_logons
