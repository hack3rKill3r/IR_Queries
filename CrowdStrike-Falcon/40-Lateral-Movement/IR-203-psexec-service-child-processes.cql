// IR-203 - PsExec Service Child Processes
// Purpose: Identify commands spawned by PSEXESVC on destination hosts.
// MITRE ATT&CK: T1569.002
#event_simpleName=ProcessRollup2
ParentBaseFileName=/^PSEXESVC\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)