// IR-195 - Rundll32 Remote Content / Script Execution
// Purpose: Identify rundll32 command lines containing remote URLs or script-protocol indicators.
// MITRE ATT&CK: T1218.011
#event_simpleName=ProcessRollup2
FileName="rundll32.exe"
CommandLine=/(https?:\/\/|javascript:|vbscript:|url\.dll)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData], limit=20000)