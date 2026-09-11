// IR-447 - IIS Worker PowerShell with Network Activity
// Purpose: Identify PowerShell spawned by IIS workers and pivotable process identifiers.
#event_simpleName=ProcessRollup2
ParentBaseFileName="w3wp.exe"
FileName=/^(powershell|pwsh)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,TargetProcessId,SHA256HashData],limit=20000)