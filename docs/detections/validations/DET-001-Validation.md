# DET-001 Validation

## Objective

## Test Environment

The detection will be validated in a controlled Windows laboratory environment.

Components:

- Windows 11 Virtual Machine
- Sysmon
- Sysmon configuration
- Wazuh Agent
- Wazuh Manager
- Splunk Enterprise
- Atomic Red Team
- PowerShell

## Test Cases

### Test Case 1

Legitimate PowerShell

`powershell.exe Get-Process`

#### Expected Result

**No alert.**

### Test Case 2

PowerShell Encoded Command

`powershell.exe -EncodedCommand <Base64>`

#### Expected Result

**Alert generated.**

### Test Case 3

Short Form

`powershell.exe -enc <Base64>`

#### Expected Result

**Alert generated.**

### Test Case 4

PowerShell 7

`pwsh.exe -EncodedCommand <Base64>`

#### Expected Result

**Alert generated.**

### Test Case 5

Office → PowerShell

Simulate:

`winword.exe` -> `powershell.exe -EncodedCommand`

#### Expected Result

**Alert generated.**

## Actual Results

## Detection Gaps

The Rule does not detect the following:
* PowerShell without -EncodedCommand.
* Encoded commands executed through other interpreters.

## Improvements

In the Upcoming versions:
* Correlate with suspicious parent processes.
* Correlate with network connections.
* Decode Base64 automatically during investigation.
* Assign risk scores based on multiple behaviors.
* Add environment-specific allow lists.

## Conclusion