// IR-071 - Browser Spawning Suspicious Child Process
// Purpose: Identify browsers launching shells or script/proxy execution binaries.
#event_simpleName=ProcessRollup2
ParentBaseFileName=/^(chrome|msedge|firefox|iexplore)\.exe$/i
FileName=/^(cmd|powershell|pwsh|mshta|wscript|cscript)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)