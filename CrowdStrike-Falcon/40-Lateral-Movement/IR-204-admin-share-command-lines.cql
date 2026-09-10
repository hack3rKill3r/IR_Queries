// IR-204 - ADMIN$ / C$ Share References
// Purpose: Identify process command lines referencing common administrative shares.
// MITRE ATT&CK: T1021.002
#event_simpleName=ProcessRollup2
CommandLine=/\\\\[^\\\s]+\\(ADMIN\$|C\$|IPC\$)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)