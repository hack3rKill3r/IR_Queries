// IR-330 - Windows Firewall Disable
// MITRE ATT&CK: T1562.004
#event_simpleName=ProcessRollup2
FileName="netsh.exe"
CommandLine=/advfirewall.*set.*(allprofiles|domainprofile|privateprofile|publicprofile).*state.*off/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)