// IR-024 - WMI Provider Child Processes
// Purpose: Identify processes spawned by WMI Provider Host, useful for remote WMI execution hunting.
// MITRE ATT&CK: T1047
#event_simpleName=ProcessRollup2
ParentBaseFileName="wmiprvse.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)