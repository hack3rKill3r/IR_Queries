// IR-053 - Shadow Copy Deletion
// Purpose: Identify common commands used to destroy Volume Shadow Copies.
// MITRE ATT&CK: T1490
#event_simpleName=ProcessRollup2
CommandLine=/(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)