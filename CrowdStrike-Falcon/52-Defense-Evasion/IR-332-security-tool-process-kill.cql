// IR-332 - Security Tool Process Termination
// Purpose: Identify taskkill/Stop-Process aimed at security products.
// MITRE ATT&CK: T1562.001
#event_simpleName=ProcessRollup2
(FileName="taskkill.exe" OR CommandLine=/Stop-Process/i)
CommandLine=/(MsMpEng|Sense|CSFalcon|SentinelAgent|Sophos|CbDefense|elastic-endpoint|savservice)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)