# DET-013 Validation

## Objective

Validate detection of suspicious local administrator account creation.

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

net user backupadmin P@ss123 /add

Expected Result:

Detection generated.

---

### Test Case 2

Command:

net localgroup administrators backupadmin /add

Expected Result:

Detection generated.

---

### Test Case 3

Command:

New-LocalUser backupadmin

Expected Result:

Detection generated.

---

### Test Case 4

Command:

Add-LocalGroupMember -Group Administrators -Member backupadmin

Expected Result:

Detection generated.

---

### Test Case 5

Legitimate administrator creates a temporary support account.

Expected Result:

Detection generated and reviewed as a potential false positive.

---

## Detection Gaps

Current limitations:

- Domain account creation
- Group Policy account deployment
- Renamed administrator accounts
- Third-party account management tools

---

## Future Improvements

- Business-hours correlation
- Authentication event correlation
- Parent process analysis
- Suspicious account name detection
- User behavior analytics

---

## Conclusion

DET-013 identifies suspicious creation of local administrator accounts and administrator group assignments. Because legitimate administrators also perform these actions, alerts should be correlated with previous detections, user activity, and authentication events before determining malicious intent.