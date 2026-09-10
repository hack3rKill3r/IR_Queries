// IR-343 - Service Persistence via SC
// Purpose: Identify creation/configuration of Windows services.
// MITRE ATT&CK: T1543.003
#event_simpleName=ProcessRollup2
FileName="sc.exe"
CommandLine=/(create|config)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)