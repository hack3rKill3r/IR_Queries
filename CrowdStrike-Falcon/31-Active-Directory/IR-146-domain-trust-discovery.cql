// IR-146 - Domain Trust Discovery
// Purpose: Identify nltest commands used to enumerate domain trusts.
// MITRE ATT&CK: T1482
#event_simpleName=ProcessRollup2
FileName="nltest.exe"
CommandLine=/(domain_trusts|trusted_domains)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)