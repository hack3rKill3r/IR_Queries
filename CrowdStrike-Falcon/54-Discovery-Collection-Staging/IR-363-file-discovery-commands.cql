// IR-363 - File and Directory Discovery
#event_simpleName=ProcessRollup2
FileName=/^(cmd|powershell|pwsh)\.exe$/i
CommandLine=/(\bdir\b|Get-ChildItem|\bgci\b|where\.exe|findstr|tree\.com)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)