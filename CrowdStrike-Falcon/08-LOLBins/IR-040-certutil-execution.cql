// IR-040 - Certutil Execution
// Purpose: Identify certutil usage for download, decode, or certificate operations.
// MITRE ATT&CK: T1105 / T1140
#event_simpleName=ProcessRollup2
FileName="certutil.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)