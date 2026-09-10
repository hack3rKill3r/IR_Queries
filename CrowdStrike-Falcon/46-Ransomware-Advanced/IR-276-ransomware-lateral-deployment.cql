// IR-276 - Ransomware Lateral Deployment Indicators
// Purpose: Identify remote execution tools combined with suspicious payload/archive names.
#event_simpleName=ProcessRollup2
(
  FileName=/^(psexec|psexec64|wmic|sc|schtasks)\.exe$/i
  OR ParentBaseFileName=/^(PSEXESVC|wmiprvse|services)\.exe$/i
)
CommandLine=/(\\ADMIN\$|\\C\$|\.exe|\.bat|\.cmd|\.ps1)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)