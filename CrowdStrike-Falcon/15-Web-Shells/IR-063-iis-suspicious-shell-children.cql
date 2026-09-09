// IR-063 - IIS Worker Spawning Shells
// Purpose: Identify high-interest shell/script interpreters spawned by w3wp.exe.
// MITRE ATT&CK: T1505.003
#event_simpleName=ProcessRollup2
ParentBaseFileName="w3wp.exe"
FileName=/^(cmd|powershell|pwsh|wscript|cscript)\.exe$/i
| table([@timestamp,ComputerName,UserName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)