// IR-491 - AS-REP Roasting Indicators
// MITRE ATT&CK: T1558.004
#event_simpleName=ProcessRollup2
CommandLine=/(asreproast|GetNPUsers|Rubeus.*asreproast)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)