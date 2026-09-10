// IR-417 - Scheduled Task Ransomware Deployment Pattern
// MITRE ATT&CK: T1053.005 / T1486
#event_simpleName=ProcessRollup2
FileName="schtasks.exe"
CommandLine=/(\/create|\/run).*(\\\\|\.exe|\.bat|\.cmd|\.ps1)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)