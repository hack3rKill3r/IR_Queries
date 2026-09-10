// IR-289 - macOS Shell Execution
// Purpose: Identify common shell execution on macOS.
// MITRE ATT&CK: T1059.004
event_platform=Mac
#event_simpleName=ProcessRollup2
FileName=/^(bash|sh|zsh)$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)