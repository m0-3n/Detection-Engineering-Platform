# DET-012 Validation

## Objective

Validate detection of suspicious scheduled task creation used for persistence.

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

schtasks.exe /create /tn "Updater" /tr "powershell.exe" /sc onlogon

Expected Result:

Detection generated.

---

### Test Case 2

Command:

schtasks.exe /create /tn "Maintenance" /tr "cmd.exe" /sc daily

Expected Result:

Detection generated.

---

### Test Case 3

Create a legitimate scheduled maintenance task.

Expected Result:

Detection generated and reviewed as a potential false positive.

---

### Test Case 4

Create a scheduled task that launches encoded PowerShell.

Expected Result:

DET-012 at creation.

DET-001 when the task executes.

---

## Detection Gaps

Current limitations:

- PowerShell ScheduledTasks module
- WMI persistence
- Registry Run Keys
- Services
- Startup Folder persistence

---

## Future Improvements

- Task XML inspection
- Suspicious task names
- Suspicious execution paths
- Process ancestry
- Task Scheduler event correlation

---

## Conclusion

DET-012 identifies scheduled task creation that launches PowerShell or Command Prompt. Although scheduled tasks are commonly used by administrators, tasks that execute scripting engines should be reviewed carefully for persistence-related activity.