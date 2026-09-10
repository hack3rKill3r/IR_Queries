// IR-156 - AS-REP Roasting Tool Strings
// Purpose: Identify common AS-REP roasting commands and tooling.
// MITRE ATT&CK: T1558.004
#event_simpleName=ProcessRollup2
CommandLine=/(asreproast|GetNPUsers|Rubeus.*asreproast)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)