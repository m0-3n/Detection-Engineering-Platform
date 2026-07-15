# DET-001 - Suspicious PowerShell Encoded Command

## Detection ID

DET-001

## Status

Draft

## Severity

High

## Author

Moinuddin

## Version

1.0

---

## Threat Overview

PowerShell is a legitimate administrative tool that is widely used by system administrators. Because it is installed by default on Windows systems and provides powerful automation capabilities, it is also frequently abused by attackers.

One common technique involves the use of the `-EncodedCommand` parameter, which allows PowerShell commands to be supplied as Base64-encoded strings.

Encoding does not provide encryption or security. Instead, attackers often use it to hide malicious commands from users and make command lines more difficult to read during investigations.

Detecting PowerShell executions that contain encoded commands provides defenders with an opportunity to identify suspicious activity early in an attack chain.

## MITRE ATT&CK Mapping

| Field     | Value      |
| --------- | ---------- |
| Tactic    | Execution  |
| Technique | T1059.001  |
| Name      | PowerShell |

### Why this mapping?

The attacker is executing commands using the PowerShell interpreter.

The use of encoded commands does not change the execution method; it changes how the commands are supplied.

This behavior therefore maps directly to Command and Scripting Interpreter: PowerShell (T1059.001).

Additional techniques such as T1027 (Obfuscated Files or Information) may also apply depending on how the encoded payload is used.

## Example Attack Scenario

An attacker gains access to a workstation through phishing.

Instead of typing readable PowerShell commands, the attacker executes:

powershell.exe -EncodedCommand SQBFAFgA...

The encoded payload downloads an additional script, disables security controls, and establishes persistence.

Although the command line appears unreadable, Windows still records the process creation event.

Detection systems monitoring command-line arguments can identify the use of the `-EncodedCommand` parameter and alert analysts for further investigation.

| Source                     | Event                                              |
| -------------------------- | -------------------------------------------------- |
| Sysmon                     | Event ID 1                                         |
| Windows Security Log       | Event ID 4688                                      |
| PowerShell Operational Log | Event ID 4104 (if Script Block Logging is enabled) |

Because encoded PowerShell is a common execution technique. I chose Sysmon Event ID 1 because it captures the process command line. I considered Event ID 4688 as an alternative, analyzed likely false positives such as SCCM and Intune, and documented follow-up investigation steps.

## Detection Logic

Generate an alert when a PowerShell process is created and the command line contains the `-EncodedCommand` argument.

Additional confidence can be obtained by identifying unusually long Base64 strings or combining this behavior with network connections or child process creation.

---

## False Positive Analysis

### Potential False Positives

The use of the `-EncodedCommand` parameter does not always indicate malicious activity. Many enterprise management and automation tools legitimately execute PowerShell commands in an encoded format for reliability and scripting convenience.

Common sources of legitimate encoded PowerShell execution include:

* Microsoft Endpoint Configuration Manager (SCCM)
* Microsoft Intune
* Enterprise automation scripts
* Software deployment and configuration management tools
* Administrative PowerShell scripts executed by system administrators

Because of these legitimate use cases, relying solely on the presence of the `-EncodedCommand` parameter may generate false positives in enterprise environments.

### False Positive Reduction

Rather than relying on a single indicator, this detection should be strengthened by correlating additional suspicious behaviors.

#### 1. Long Base64-Encoded Payloads

Encoded commands containing unusually long Base64 strings may indicate complex or heavily obfuscated payloads rather than simple administrative commands.

Detection logic can be enhanced by identifying encoded commands that exceed an environment-specific length threshold. The threshold should be determined through observation and tuning within the target environment.

#### 2. Suspicious Parent Processes

Increase the confidence of the detection when PowerShell is launched by processes that do not typically execute PowerShell.

Examples include:

* `winword.exe`
* `excel.exe`
* `outlook.exe`
* `mshta.exe`
* `wscript.exe`
* `cscript.exe`

Office applications or scripting engines spawning encoded PowerShell are generally more suspicious than PowerShell launched directly by an approved management tool.

#### 3. Child Process Creation

Investigate whether the PowerShell process spawns additional processes immediately after execution.

Examples include:

* `cmd.exe`
* `rundll32.exe`
* `regsvr32.exe`
* `certutil.exe`
* `msiexec.exe`

This behavior may indicate that PowerShell is being used as part of a larger attack chain.

#### 4. Network Activity

Increase detection confidence if the encoded PowerShell process initiates outbound network connections shortly after execution.

Particular attention should be given to:

* Connections to unfamiliar external IP addresses
* Downloads of scripts or executables
* Communication with infrastructure that is not normally contacted by the host

Network activity combined with encoded PowerShell execution provides stronger evidence of malicious behavior than either event alone.

#### 5. User Context

Evaluate the account responsible for executing the command.

Additional investigation should be performed when the activity originates from:

* Standard user accounts
* Unexpected service accounts
* Accounts executing PowerShell outside their normal operational patterns

User context can significantly improve the accuracy of an investigation.

#### 6. Environment-Specific Allow Lists

Organizations may choose to exclude approved administrative tooling that legitimately uses encoded PowerShell.

Examples include:

* Approved configuration management platforms
* Internal automation servers
* Known maintenance scripts
* Organization-specific deployment tools

Allow lists should be reviewed regularly to ensure that legitimate administrative activity is excluded without masking malicious behavior.

### Detection Engineering Consideration

The use of `-EncodedCommand` should be treated as an initial indicator rather than definitive evidence of malicious activity.

Higher-confidence detections are achieved by correlating multiple telemetry sources and behavioral indicators. For example, encoded PowerShell execution combined with a suspicious parent process, outbound network communication, or the creation of additional processes provides a much stronger indication of malicious activity while reducing false positives.



