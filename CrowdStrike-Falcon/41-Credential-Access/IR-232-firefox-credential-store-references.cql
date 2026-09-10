// IR-232 - Firefox Credential Store References
// Purpose: Identify references to Firefox key4.db and logins.json credential stores.
// MITRE ATT&CK: T1555.003
#event_simpleName=ProcessRollup2
CommandLine=/(key4\.db|logins\.json)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)