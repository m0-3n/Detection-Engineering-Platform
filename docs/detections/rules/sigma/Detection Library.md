# All MITRE ATT&CK Tactic Mappings:

| Tactic                                      | Detection IDs                      |
| ------------------------------------------- | ---------------------------------- |
| Execution                                   | DET-001 to DET-006                 |
| Defense Evasion                             | DET-007, DET-008, DET-009, DET-014 |
| Lateral Movement                            | DET-010, DET-011                   |
| Persistence                                 | DET-012                            |
| Privilege Escalation / Account Manipulation | DET-013                            |
| Credential Access                           | DET-015                            |


# List of Sigma Detections... and its progress

| ID        | Detection                            | MITRE Technique   | Difficulty |Progress   |
| --------- | ------------------------------------ | ----------------- | ---------- |---------- |
| DET-001   | Encoded PowerShell                   | T1059.001         | Easy       | Done      |
| DET-002   | PowerShell DownloadString            | T1105 / T1059.001 | Easy       | Done      |
| DET-003   | Execution Policy Bypass              | T1059.001         | Easy       | Done      |
| DET-004   | Hidden PowerShell Window             | T1564             | Easy       | Done      |
| DET-005   | Suspicious PowerShell Parent Process | T1204 / T1059.001 | Medium     | Done      |
| DET-006   | PowerShell Web Request               | T1105             | Medium     | Done      |
| DET-007   | Certutil Download                    | T1105             | Medium     | Done      |
| DET-008   | Rundll32 Suspicious Execution        | T1218.011         | Medium     | Done      |
| DET-009   | Regsvr32 Remote Script Execution     | T1218.010         | Medium     | Done      |
| DET-010   | WMI Process Creation                 | T1047             | Medium     | Done      |
| DET-011   | PsExec Execution                     | T1021.002         | Medium     | Done      |
| DET-012   | Scheduled Task Creation              | T1053.005         | Medium     | Done      |
| DET-013   | New Local Administrator Account      | T1136             | Medium     | Done      |
| DET-014   | Defender Tampering                   | T1562.001         | High       | Done      |
| DET-015   | LSASS Memory Dump Attempt            | T1003.001         | High       | Done      |
