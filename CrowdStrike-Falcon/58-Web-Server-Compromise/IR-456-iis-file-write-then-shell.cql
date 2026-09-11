// IR-456 - IIS File Write / Shell Pivot
// Purpose: Review web-root writes and suspicious shell execution on the same host.
(
 #event_simpleName=/FileWritten$/
 FilePath=/\\inetpub\\wwwroot\\/i
)
OR
(
 #event_simpleName=ProcessRollup2
 ParentBaseFileName="w3wp.exe"
 FileName=/^(cmd|powershell|pwsh|rundll32|wscript|cscript|mshta)\.exe$/i
)
| table([@timestamp,#event_simpleName,ComputerName,UserName,ContextBaseFileName,ParentBaseFileName,FileName,CommandLine,TargetFileName,FilePath],limit=20000)