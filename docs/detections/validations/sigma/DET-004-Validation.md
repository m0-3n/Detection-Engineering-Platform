# DET-004 Validation

## Objective

Validate detection of hidden PowerShell execution.

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

powershell.exe -WindowStyle Hidden

Expected Result:

Detection generated.

---

### Test Case 2

Command:

powershell.exe -w hidden

Expected Result:

Detection generated.

---

### Test Case 3

Command:

powershell.exe

Expected Result:

No detection.

---

### Test Case 4

Enterprise automation using hidden PowerShell.

Expected Result:

Detection generated and reviewed as a potential false positive.

---

## Detection Gaps

Current limitations:

- PowerShell hosted through APIs
- Obfuscated command lines
- Alternate execution mechanisms
- LOLBins replacing PowerShell

---

## Future Improvements

- Correlate with DET-001
- Correlate with DET-002
- Correlate with DET-003
- Parent process analysis
- Child process analysis

---

## Conclusion

DET-004 detects PowerShell processes executing with hidden window parameters. Although legitimate administrative automation may generate alerts, this behavior frequently appears in malware and post-exploitation activity and should be investigated alongside related detections.