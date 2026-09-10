// IR-290 - macOS osascript Execution
// Purpose: Identify AppleScript/JXA execution.
// MITRE ATT&CK: T1059.002
event_platform=Mac
#event_simpleName=ProcessRollup2
FileName="osascript"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)