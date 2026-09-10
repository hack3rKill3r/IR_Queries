// IR-350 - Accessibility Feature Abuse
// Purpose: Hunt for replacement/modification of utilman, sethc, osk, narrator, magnify.
// MITRE ATT&CK: T1546.008
#event_simpleName=ProcessRollup2
CommandLine=/(utilman\.exe|sethc\.exe|osk\.exe|narrator\.exe|magnify\.exe)/i
CommandLine=/(copy|move|rename|takeown|icacls|cmd\.exe|powershell)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)