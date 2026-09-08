// IR-030 - NLTEST Execution
// Purpose: Identify domain, trust, and domain-controller discovery with nltest.
// MITRE ATT&CK: T1018 / T1482
#event_simpleName=ProcessRollup2
FileName="nltest.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)