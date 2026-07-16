# DET-003 Validation

## Objective

Validate detection of PowerShell execution policy bypass activity.

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

powershell.exe -ExecutionPolicy Bypass script.ps1

Expected Result:

Detection generated.

---

### Test Case 2

Command:

powershell.exe -ep bypass script.ps1

Expected Result:

Detection generated.

---

### Test Case 3

Command:

powershell.exe script.ps1

Expected Result:

No detection.

---

### Test Case 4

Legitimate enterprise deployment.

Expected Result:

Detection generated but classified as a potential false positive.

---

## Detection Gaps

Current limitations:

- Encoded commands hiding execution policy
- In-memory PowerShell hosting
- Execution policy changed inside the script
- PowerShell APIs that do not expose command-line arguments

---

## Future Improvements

- Correlate with DET-001
- Correlate with DET-002
- Parent process analysis
- Child process analysis
- Threat intelligence enrichment

---

## Conclusion

DET-003 identifies PowerShell processes attempting to bypass execution policy restrictions. While execution policy is not a security boundary, its bypass is frequently associated with attacker tradecraft and should be investigated alongside other suspicious activity.