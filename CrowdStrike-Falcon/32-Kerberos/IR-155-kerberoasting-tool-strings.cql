// IR-155 - Kerberoasting Tool Strings
// Purpose: Identify common Kerberoasting tooling and command-line indicators.
// MITRE ATT&CK: T1558.003
#event_simpleName=ProcessRollup2
CommandLine=/(kerberoast|Invoke-Kerberoast|GetUserSPNs|Rubeus.*kerberoast)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)