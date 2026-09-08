// IR-022 - PSEXESVC Execution
// Purpose: Identify the PsExec service-side component on destination hosts.
// MITRE ATT&CK: T1569.002
#event_simpleName=ProcessRollup2
FileName=/^PSEXESVC\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)