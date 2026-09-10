// IR-181 - Office -> CMD -> PowerShell Chain
// Purpose: Correlate an Office application spawning cmd.exe which then launches PowerShell.
// MITRE ATT&CK: T1204.002 / T1059.001
event_platform=Win
| correlate(
  grandparent: {
    #event_simpleName=ProcessRollup2
    FileName=/^(winword|excel|powerpnt|outlook)\.exe$/i
    CommandLine=*
  } include:[aid,TargetProcessId,ParentProcessId,ComputerName,UserName,FileName,CommandLine],
  parent: {
    #event_simpleName=ProcessRollup2
    FileName="cmd.exe"
    CommandLine=*
    | aid <=> grandparent.aid
    | ParentProcessId <=> grandparent.TargetProcessId
  } include:[aid,TargetProcessId,ParentProcessId,ComputerName,UserName,FileName,CommandLine],
  child: {
    #event_simpleName=ProcessRollup2
    FileName=/^(powershell|pwsh)\.exe$/i
    CommandLine=*
    | aid <=> parent.aid
    | ParentProcessId <=> parent.TargetProcessId
  } include:[aid,TargetProcessId,ParentProcessId,ComputerName,UserName,FileName,CommandLine],
  sequence=true,
  within=10m
)