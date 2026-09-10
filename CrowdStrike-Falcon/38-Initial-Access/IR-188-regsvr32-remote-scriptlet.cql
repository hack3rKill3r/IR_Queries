// IR-188 - Regsvr32 Remote Scriptlet
// Purpose: Identify regsvr32 patterns commonly associated with remote scriptlet execution.
// MITRE ATT&CK: T1218.010
#event_simpleName=ProcessRollup2
FileName="regsvr32.exe"
CommandLine=/(scrobj\.dll|https?:\/\/|\/i:)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData], limit=20000)