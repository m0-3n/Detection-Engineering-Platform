# DET-014 Validation

## Objective

Validate detection of Microsoft Defender tampering attempts.

---

## Test Environment

- Windows 11 VM
- Sysmon
- Wazuh Agent
- Wazuh Manager
- Splunk Enterprise

---

## Test Cases

### Test Case 1

Command:

Set-MpPreference -DisableRealtimeMonitoring $true

Expected Result:

Detection generated.

---

### Test Case 2

Command:

Set-MpPreference -DisableBehaviorMonitoring $true

Expected Result:

Detection generated.

---

### Test Case 3

Command:

Set-MpPreference -DisableScriptScanning $true

Expected Result:

Detection generated.

---

### Test Case 4

Command:

sc stop WinDefend

Expected Result:

Detection generated.

---

### Test Case 5

Command:

reg add HKLM\SOFTWARE\Microsoft\Windows Defender

Expected Result:

Detection generated.

---

### Test Case 6

Legitimate administrator temporarily disables Defender for maintenance.

Expected Result:

Detection generated and reviewed as a potential false positive.

---

## Detection Gaps

Current limitations:

- Defender exclusions
- Group Policy modifications
- Tamper Protection bypass
- Defender for Endpoint cloud settings

---

## Future Improvements

- Detect exclusion abuse
- Correlate with LSASS dumping
- Parent process scoring
- Business-hours analysis
- User behavior analytics

---

## Conclusion

DET-014 detects common Microsoft Defender tampering techniques used during post-exploitation. Alerts should be correlated with previous execution, persistence, and privilege escalation detections to determine malicious intent and reduce false positives.