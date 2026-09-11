// IR-499 - Credential Access -> Lateral Movement Chain
// Purpose: Correlate credential-access indicators with subsequent remote execution on the same user/endpoint.
correlate(
 cred:{
  #event_simpleName=ProcessRollup2
  CommandLine=/(lsass|mimikatz|secretsdump|sam.*save|ntds\.dit|dcsync|Rubeus.*(dump|ptt))/i
 } include:[aid,ComputerName,UserName,TargetProcessId,FileName,CommandLine],
 lateral:{
  #event_simpleName=ProcessRollup2
  (FileName=/^(psexec|psexec64|wmic|mstsc|sc|schtasks)\.exe$/i OR ParentBaseFileName=/^(PSEXESVC|wmiprvse|wsmprovhost)\.exe$/i)
  | aid <=> cred.aid
  | UserName <=> cred.UserName
 } include:[aid,ComputerName,UserName,FileName,CommandLine],
 sequence=true,
 within=120m
)