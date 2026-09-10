// IR-227 - Registry Hive Save Broad Hunt
// Purpose: Find commands saving SAM, SYSTEM, SECURITY, or related hives.
// MITRE ATT&CK: T1003.002
#event_simpleName=ProcessRollup2
FileName="reg.exe"
CommandLine=/\bsave\b.*(SAM|SYSTEM|SECURITY)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)