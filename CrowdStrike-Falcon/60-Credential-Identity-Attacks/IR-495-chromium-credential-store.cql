// IR-495 - Chromium Credential Store References
// MITRE ATT&CK: T1555.003
#event_simpleName=ProcessRollup2
CommandLine=/(Login Data|Web Data|Local State|Cookies)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)