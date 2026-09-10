// IR-318 - kubectl exec
// Purpose: Identify interactive/remote command execution in Kubernetes workloads.
// MITRE ATT&CK: T1609.004
#event_simpleName=ProcessRollup2
FileName=/^kubectl$/i
CommandLine=/\bexec\b/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData],limit=20000)