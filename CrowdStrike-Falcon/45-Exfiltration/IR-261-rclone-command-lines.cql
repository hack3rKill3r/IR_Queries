// IR-261 - Rclone Command-Line Review
// Purpose: Identify rclone usage and remote destination syntax.
// MITRE ATT&CK: T1567.002
#event_simpleName=ProcessRollup2
FileName="rclone.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)