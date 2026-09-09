// IR-062 - IIS Worker Child Processes
// Purpose: Review processes spawned by w3wp.exe for possible web-shell execution.
// MITRE ATT&CK: T1505.003
#event_simpleName=ProcessRollup2
ParentBaseFileName="w3wp.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)