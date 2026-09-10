// IR-220 - Lateral Movement Super Query
// Purpose: Broad first-pass hunt across common remote execution and lateral movement mechanisms.
#event_simpleName=ProcessRollup2
(
  FileName=/^(psexec|psexec64|wmic|mstsc|wsmprovhost|sc|schtasks)\.exe$/i
  OR ParentBaseFileName=/^(PSEXESVC|wmiprvse|wsmprovhost|services)\.exe$/i
  OR CommandLine=/(\\ADMIN\$|\\C\$|\/node:|Enter-PSSession|Invoke-Command|New-PSSession|impacket-(psexec|wmiexec|smbexec))/i
)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData,TargetProcessId,ParentProcessId], limit=20000)