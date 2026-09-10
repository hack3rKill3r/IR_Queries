// IR-216 - PowerShell Remoting Strings
// Purpose: Identify common PowerShell remoting commands.
// MITRE ATT&CK: T1021.006
#event_simpleName=ProcessRollup2
FileName=/^(powershell|pwsh)\.exe$/i
CommandLine=/(Enter-PSSession|Invoke-Command|New-PSSession|ComputerName|SessionOption)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)