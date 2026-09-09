// IR-056 - Recovery Destruction Commands
// Purpose: Broad hunt for commands intended to inhibit system recovery.
// MITRE ATT&CK: T1490
#event_simpleName=ProcessRollup2
CommandLine=/(delete.*shadows|shadowcopy.*delete|delete.*catalog|recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)