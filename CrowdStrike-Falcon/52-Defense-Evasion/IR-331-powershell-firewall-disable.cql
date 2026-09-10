// IR-331 - PowerShell Firewall Disable
// MITRE ATT&CK: T1562.004
#event_simpleName=ProcessRollup2
CommandLine=/Set-NetFirewallProfile.*Enabled.*False/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)