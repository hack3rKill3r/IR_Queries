// IR-033 - DSQuery Execution
// Purpose: Identify Active Directory queries performed with dsquery.exe.
// MITRE ATT&CK: T1087.002 / T1018
#event_simpleName=ProcessRollup2
FileName="dsquery.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)