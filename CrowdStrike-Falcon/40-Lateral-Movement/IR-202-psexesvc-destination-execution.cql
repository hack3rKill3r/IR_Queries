// IR-202 - PSEXESVC Destination Execution
// Purpose: Identify PsExec service-side execution on destination systems.
// MITRE ATT&CK: T1569.002
#event_simpleName=ProcessRollup2
FileName=/^PSEXESVC\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData,ParentProcessId], limit=20000)