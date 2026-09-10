// IR-190 - BITSAdmin Transfer
// Purpose: Identify BITSAdmin transfer/download behavior.
// MITRE ATT&CK: T1197
#event_simpleName=ProcessRollup2
FileName="bitsadmin.exe"
CommandLine=/(\/transfer|\/addfile|https?:\/\/)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData], limit=20000)