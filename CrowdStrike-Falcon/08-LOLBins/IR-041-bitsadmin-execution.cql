// IR-041 - BITSAdmin Execution
// Purpose: Identify BITSAdmin use, including file transfer and job creation.
// MITRE ATT&CK: T1197
#event_simpleName=ProcessRollup2
FileName="bitsadmin.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)