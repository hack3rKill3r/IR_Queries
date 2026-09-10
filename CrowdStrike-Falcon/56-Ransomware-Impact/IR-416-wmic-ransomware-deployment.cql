// IR-416 - WMIC Ransomware Deployment Pattern
// MITRE ATT&CK: T1047 / T1486
#event_simpleName=ProcessRollup2
FileName="wmic.exe"
CommandLine=/(\/node:|process\s+call\s+create)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)