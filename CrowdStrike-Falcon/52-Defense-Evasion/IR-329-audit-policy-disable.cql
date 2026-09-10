// IR-329 - Audit Policy Disable/Reduction
// Purpose: Identify auditpol commands reducing Windows auditing.
// MITRE ATT&CK: T1562.002
#event_simpleName=ProcessRollup2
FileName="auditpol.exe"
CommandLine=/(\/set|\/clear).*(failure:disable|success:disable|\/success:disable|\/failure:disable|\/clear)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)