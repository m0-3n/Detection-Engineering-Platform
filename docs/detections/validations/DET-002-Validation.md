# DET-002 Validation

## Objective

Validate detection of PowerShell remote content retrieval while minimizing false positives.

---

## Test Environment

- Windows 11 Virtual Machine
- Sysmon
- Wazuh Agent
- Wazuh Manager
- Splunk Enterprise
- Atomic Red Team

---

## Test Cases

### Test Case 1

Command:

```powershell
Invoke-WebRequest https://example.com
```

Expected Result:

Detection generated.

---

### Test Case 2

Command:

```powershell
Invoke-RestMethod https://example.com
```

Expected Result:

Detection generated.

---

### Test Case 3

Command:

```powershell
(New-Object Net.WebClient).DownloadString(...)
```

Expected Result:

Detection generated.

---

### Test Case 4

Legitimate enterprise automation.

Expected Result:

Detection generated but classified as a potential false positive requiring analyst review.

---

## Detection Gaps

Current limitations include:

- curl.exe downloads
- certutil.exe downloads
- BITS transfers
- Custom .NET networking implementations
- Encrypted or obfuscated PowerShell commands that avoid the monitored function names

---

## Future Improvements

- Correlate with DNS events
- Correlate with network connections
- Integrate threat intelligence
- Automatic URL extraction
- Parent process analysis
- Child process correlation

---

## Conclusion

DET-002 provides visibility into PowerShell-based remote content retrieval by monitoring commonly abused networking functionality. While legitimate administrative activity may trigger this detection, combining it with network telemetry, parent process analysis, and threat intelligence can significantly improve confidence.