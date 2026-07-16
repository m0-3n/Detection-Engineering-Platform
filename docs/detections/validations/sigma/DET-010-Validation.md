# DET-010 Validation

## Objective

Validate detection of WMI remote process creation.

---

## Test Environment

- Windows 11 VM
- Sysmon
- Wazuh Agent
- Wazuh Manager
- Splunk Enterprise
- Two Windows hosts
- Atomic Red Team

---

## Test Cases

### Test Case 1

Command:

wmic /node:TARGET process call create "powershell.exe"

Expected Result:

Detection generated.

---

### Test Case 2

Command:

wmic /node:TARGET process call create "cmd.exe"

Expected Result:

Detection generated.

---

### Test Case 3

Legitimate WMI query:

wmic os get caption

Expected Result:

No detection.

---

### Test Case 4

Enterprise inventory software performing WMI queries.

Expected Result:

No detection.

---

## Detection Gaps

Current limitations:

- WinRM
- DCOM
- PsExec
- Scheduled Tasks
- WMI via PowerShell cmdlets

---

## Future Improvements

- Authentication correlation
- Remote IP correlation
- Parent process analysis
- WinRM correlation
- Process ancestry

---

## Conclusion

DET-010 identifies suspicious WMI remote process creation by detecting remote process execution commands. Since WMI is widely used in enterprise administration, analysts should correlate alerts with authentication events, parent processes, and subsequent activity before determining malicious intent.