// IR-143 - NET LocalGroup Enumeration
// Purpose: Identify local group discovery, including local Administrators membership review.
// MITRE ATT&CK: T1069.001
#event_simpleName=ProcessRollup2
FileName=/^(net|net1)\.exe$/i
CommandLine=/\blocalgroup\b/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)