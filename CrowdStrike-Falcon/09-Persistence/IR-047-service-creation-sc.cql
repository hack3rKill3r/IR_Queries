// IR-047 - Service Creation with SC
// Purpose: Identify service creation through sc.exe.
// MITRE ATT&CK: T1543.003
#event_simpleName=ProcessRollup2
FileName="sc.exe"
CommandLine=/\bcreate\b/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)