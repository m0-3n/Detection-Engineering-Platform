# DET-006 Validation

## Objective

Validate detection of PowerShell network communication activity.

---

## Test Environment

- Windows 11 VM
- Sysmon
- Wazuh Agent
- Wazuh Manager
- Splunk Enterprise
- Atomic Red Team

---

## Test Cases

### Test Case 1

Command:

Invoke-WebRequest https://example.com

Expected Result:

Detection generated.

---

### Test Case 2

Command:

Invoke-RestMethod https://example.com

Expected Result:

Detection generated.

---

### Test Case 3

Command:

[System.Net.WebClient]::new()

Expected Result:

Detection generated.

---

### Test Case 4

Legitimate administrative automation.

Expected Result:

Detection generated and reviewed for legitimacy.

---

## Detection Gaps

Current limitations:

- curl.exe
- certutil.exe
- BITS transfers
- Custom networking implementations
- PowerShell obfuscation

---

## Future Improvements

- DNS correlation
- Threat intelligence
- Parent process analysis
- Beacon detection
- Network telemetry enrichment

---

## Conclusion

DET-006 provides visibility into PowerShell network communication. While legitimate administrative tasks may generate alerts, correlating this detection with additional suspicious behaviors significantly increases confidence in identifying attacker activity.