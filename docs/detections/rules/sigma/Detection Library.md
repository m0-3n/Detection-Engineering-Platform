# List of Sigma Detections...

| ID        | Detection                            | MITRE Technique   | Difficulty |
| --------- | ------------------------------------ | ----------------- | ---------- |
| DET-001   | Encoded PowerShell                   | T1059.001         | Easy       |
| DET-002   | PowerShell DownloadString            | T1105 / T1059.001 | Easy       |
| DET-003   | Execution Policy Bypass              | T1059.001         | Easy       |
| DET-004   | Hidden PowerShell Window             | T1564             | Easy       |
| DET-005   | Suspicious PowerShell Parent Process | T1204 / T1059.001 | Medium     |
| DET-006   | PowerShell Web Request               | T1105             | Medium     |
| DET-007   | Certutil Download                    | T1105             | Medium     |
| DET-008   | Rundll32 Suspicious Execution        | T1218.011         | Medium     |
| DET-009   | Regsvr32 Remote Script Execution     | T1218.010         | Medium     |
| DET-010   | WMI Process Creation                 | T1047             | Medium     |
| DET-011   | PsExec Execution                     | T1021.002         | Medium     |
| DET-012   | Scheduled Task Creation              | T1053.005         | Medium     |
| DET-013   | New Local Administrator Account      | T1136             | Medium     |
| DET-014   | Defender Tampering                   | T1562.001         | High       |
| DET-015   | LSASS Memory Dump Attempt            | T1003.001         | High       |
