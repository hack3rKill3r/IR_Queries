// IR-159 - NTDSUtil Execution
// Purpose: Identify ntdsutil.exe usage for legitimate administration or possible credential acquisition.
// MITRE ATT&CK: T1003.003
#event_simpleName=ProcessRollup2
FileName="ntdsutil.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)