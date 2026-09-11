// IR-496 - Firefox Credential Store References
// MITRE ATT&CK: T1555.003
#event_simpleName=ProcessRollup2
CommandLine=/(key4\.db|logins\.json|cookies\.sqlite|places\.sqlite)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)