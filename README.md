# SOC L1 Threat Hunting Lab – Boss of the SOC v1

**Objective**: Demonstrate SPL troubleshooting, schema discovery, and MITRE ATT&CK mapping on non-standard SOC data. Built for UST/Genpact/TechM SOC L1/L2 interviews.

### Detection 1: T1110 Brute Force – Non-Standard Schema Analysis
**Challenge**: BOTSv1 attack-only dataset uses URL-encoded proxy logs, not Windows Event XML.

**SPL**: 
```spl
index=botsv1 sourcetype=botsv1 4625 | stats count
