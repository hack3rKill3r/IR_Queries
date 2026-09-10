// IR-404 - BCDEdit Recovery Disable
// MITRE ATT&CK: T1490
#event_simpleName=ProcessRollup2
FileName="bcdedit.exe"
CommandLine=/(recoveryenabled.*no|bootstatuspolicy.*ignoreallfailures)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)