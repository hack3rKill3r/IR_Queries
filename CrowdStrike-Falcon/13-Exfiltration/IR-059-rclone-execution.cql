// IR-059 - Rclone Execution
// Purpose: Identify rclone usage for cloud synchronization or potential exfiltration.
// MITRE ATT&CK: T1567.002
#event_simpleName=ProcessRollup2
FileName="rclone.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FilePath,CommandLine,SHA256HashData], limit=20000)