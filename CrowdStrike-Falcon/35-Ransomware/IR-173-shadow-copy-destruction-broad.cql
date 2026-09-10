// IR-173 - Broad Shadow Copy Destruction
// Purpose: Identify multiple common shadow-copy deletion methods.
// MITRE ATT&CK: T1490
#event_simpleName=ProcessRollup2
CommandLine=/(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|Get-WmiObject.*Win32_ShadowCopy|Get-CimInstance.*Win32_ShadowCopy)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)