# IR-017 - Explorer Spawning Shells
# Useful for ClickFix and social-engineering investigations.
#event_simpleName=ProcessRollup2
ParentBaseFileName="explorer.exe"
FileName=/^(cmd|powershell|pwsh|mshta|wscript|cscript)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)