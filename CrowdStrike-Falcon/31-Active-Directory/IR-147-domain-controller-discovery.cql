// IR-147 - Domain Controller Discovery
// Purpose: Identify nltest-based domain controller discovery.
// MITRE ATT&CK: T1018
#event_simpleName=ProcessRollup2
FileName="nltest.exe"
CommandLine=/(dclist|dsgetdc)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)