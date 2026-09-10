// IR-405 - Cipher Free-Space Wipe
// Purpose: Identify cipher /w use that can destroy recoverable data.
// MITRE ATT&CK: T1070.004 / T1485
#event_simpleName=ProcessRollup2
FileName="cipher.exe"
CommandLine=/\/w:/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)