// IR-055 - BCDEdit Execution
// Purpose: Identify boot configuration changes, including recovery-related ransomware preparation.
// MITRE ATT&CK: T1490
#event_simpleName=ProcessRollup2
FileName="bcdedit.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)