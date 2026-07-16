# DET-011 Validation

## Objective

Validate detection of PsExec remote process execution.

---

## Test Environment

- Windows 11 VM (Host 1)
- Windows 11 VM (Host 2)
- Sysmon
- Wazuh Agent
- Wazuh Manager
- Splunk Enterprise
- PsExec

---

## Test Cases

### Test Case 1

Command:

PsExec.exe \\TARGET powershell.exe

Expected Result:

Detection generated.

---

### Test Case 2

Command:

PsExec.exe \\TARGET cmd.exe

Expected Result:

Detection generated.

---

### Test Case 3

Legitimate PsExec administrative maintenance.

Expected Result:

Detection generated and reviewed as a potential false positive.

---

### Test Case 4

PsExec launching encoded PowerShell.

Expected Result:

DET-011 on Host 1.

DET-001 on Host 2.

---

## Detection Gaps

Current limitations:

- WinRM
- WMI
- Scheduled Tasks
- DCOM
- Remote Desktop

---

## Future Improvements

- Detect PSEXESVC service creation.
- Authentication correlation.
- SMB session monitoring.
- Process ancestry.
- Multi-host correlation.

---

## Conclusion

DET-011 detects PsExec-based remote process execution. Although PsExec is widely used by administrators, correlating this activity with encoded PowerShell, network communication, and authentication events significantly improves confidence in identifying malicious lateral movement.