# DET-005 Validation

## Objective

Validate detection of PowerShell launched by suspicious parent processes.

---

## Test Environment

- Windows 11 VM
- Sysmon
- Wazuh Agent
- Wazuh Manager
- Splunk Enterprise
- Microsoft Office
- Atomic Red Team

---

## Test Cases

### Test Case 1

PowerShell launched from Word macro.

Expected Result:

Detection generated.

---

### Test Case 2

PowerShell launched from Excel macro.

Expected Result:

Detection generated.

---

### Test Case 3

PowerShell launched from explorer.exe.

Expected Result:

No detection.

---

### Test Case 4

Legitimate Office automation.

Expected Result:

Detection generated and reviewed for legitimacy.

---

## Detection Gaps

Current limitations:

- Process ancestry is not evaluated.
- Indirect execution through cmd.exe or wscript.exe.
- PowerShell hosted through .NET APIs.
- WMI-based execution.

---

## Future Improvements

- Process ancestry analysis
- Office macro telemetry
- Email correlation
- Child process correlation
- Risk scoring

---

## Conclusion

DET-005 detects PowerShell execution initiated by applications that rarely require scripting functionality. Correlating this detection with encoded commands, hidden windows, or network activity significantly increases confidence that the observed behavior is malicious.