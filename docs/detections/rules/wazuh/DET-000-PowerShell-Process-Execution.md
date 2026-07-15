# DET-000 - PowerShell Process Execution

## Purpose

This detection identifies PowerShell process creation events. It is intended to serve as a reusable foundation for PowerShell-focused detections rather than to identify malicious activity on its own.

## Telemetry

| Source           | Event         |
| ---------------- | ------------- |
| Sysmon           | Event ID 1    |
| Windows Security | Event ID 4688 |

## Detection Logic

Generate a detection whenever a PowerShell process (powershell.exe or pwsh.exe) is created.

## Expected Behavior

Should detect:

`powershell.exe`
`pwsh.exe`

Should not detect:

`cmd.exe`
`explorer.exe`
`notepad.exe`

## Limitations

This detection does not determine whether PowerShell usage is malicious.
It simply identifies PowerShell execution.

## Future Child Detections

DET-001 – Encoded Command
DET-002 – DownloadString
DET-003 – Execution Policy Bypass
DET-004 – Hidden Window
DET-005 – AMSI Bypass
DET-006 – Suspicious Parent Process
DET-007 – PowerShell Network Download
<!-- more to be written. -->