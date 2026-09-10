// IR-174 - Disable Windows Recovery
// Purpose: Identify BCDEdit patterns used to inhibit recovery.
// MITRE ATT&CK: T1490
#event_simpleName=ProcessRollup2
CommandLine=/(recoveryenabled.*no|bootstatuspolicy.*ignoreallfailures)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)