// IR-161 - Registry Hive Save
// Purpose: Identify attempts to save SAM, SECURITY, or SYSTEM hives for offline credential extraction.
// MITRE ATT&CK: T1003.002
#event_simpleName=ProcessRollup2
FileName="reg.exe"
CommandLine=/save.*(sam|security|system)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)