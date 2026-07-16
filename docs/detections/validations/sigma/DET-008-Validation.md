# DET-008 Validation

## Objective

Validate detection of suspicious Rundll32 execution using script-based arguments.

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

rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"

Expected Result:

Detection generated.

---

### Test Case 2

Execute a legitimate Windows Control Panel applet.

Expected Result:

No detection.

---

### Test Case 3

Execute a vendor utility that legitimately invokes Rundll32.

Expected Result:

No detection.

---

### Test Case 4

Execute Rundll32 after downloading a malicious DLL with Certutil.

Expected Result:

DET-007 and DET-008 correlation.

---

## Detection Gaps

Current limitations:

- Legitimate DLL execution cannot be differentiated solely by command line.
- Reflective DLL loading.
- Custom DLL loaders.
- Alternate LOLBins.

---

## Future Improvements

- Detect DLLs executing from Downloads or AppData.
- Parent process allowlists.
- Process ancestry analysis.
- File reputation checks.

---

## Conclusion

DET-008 detects suspicious Rundll32 usage by identifying script-based execution patterns frequently associated with LOLBin abuse. Correlating this detection with previous payload download activity significantly improves confidence.