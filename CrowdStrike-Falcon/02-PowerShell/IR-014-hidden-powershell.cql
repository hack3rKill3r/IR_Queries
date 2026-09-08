# IR-014 - Hidden PowerShell
#event_simpleName=ProcessRollup2
FileName=/^(powershell|pwsh)\.exe$/i
CommandLine=/(WindowStyle\s+Hidden|-w\s+hidden|-windowstyle\s+hidden)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)