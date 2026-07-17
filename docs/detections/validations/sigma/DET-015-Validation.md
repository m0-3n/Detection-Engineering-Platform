# DET-015 Validation

## Objective

Validate detection of LSASS memory dumping techniques commonly used for credential theft.

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

procdump.exe -ma lsass.exe lsass.dmp

Expected Result:

Detection generated.

---

### Test Case 2

Command:

rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump

Expected Result:

Detection generated.

---

### Test Case 3

Command:

sekurlsa::logonpasswords

Expected Result:

Detection generated.

---

### Test Case 4

Execute NanoDump.

Expected Result:

Detection generated.

---

### Test Case 5

Create lsass.dmp.

Expected Result:

Detection generated.

---

### Test Case 6

Authorized incident responder acquires memory from LSASS.

Expected Result:

Detection generated and reviewed as a potential false positive.

---

## Detection Gaps

Current limitations:

- Direct syscalls
- Custom dump tools
- Kernel-mode dumping
- PPL bypasses
- Handle duplication attacks

---

## Future Improvements

- Sysmon Event ID 10 correlation
- File creation monitoring
- ETW telemetry
- Multi-stage attack correlation
- Cross-host credential reuse detection

---

## Conclusion

DET-015 detects multiple techniques used to dump LSASS memory for credential theft. Alerts should be treated as high priority and correlated with previous execution, defense evasion, and lateral movement detections to identify active post-exploitation activity.