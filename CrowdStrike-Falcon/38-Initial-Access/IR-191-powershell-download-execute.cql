// IR-191 - PowerShell Download + Execute
// Purpose: Identify PowerShell command lines combining retrieval and execution semantics.
// MITRE ATT&CK: T1059.001 / T1105
#event_simpleName=ProcessRollup2
FileName=/^(powershell|pwsh)\.exe$/i
CommandLine=/(invoke-webrequest|iwr|irm|downloadstring|downloadfile|webclient|https?:\/\/)/i
CommandLine=/(iex|invoke-expression|start-process|&\s|\.exe|\.dll)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData], limit=20000)