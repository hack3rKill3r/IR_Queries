// IR-229 - Shadow Copy Creation
// Purpose: Identify shadow-copy creation that may precede offline credential access.
// MITRE ATT&CK: T1003.003
#event_simpleName=ProcessRollup2
FileName="vssadmin.exe"
CommandLine=/create.*shadow/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)