// IR-379 - Discovery -> Lateral Movement Chain
correlate(
 discovery:{#event_simpleName=ProcessRollup2 FileName=/^(nltest|net|net1|dsquery|quser|qwinsta|ipconfig|whoami)\.exe$/i} include:[aid,ComputerName,UserName,TargetProcessId,FileName,CommandLine],
 lateral:{#event_simpleName=ProcessRollup2 (FileName=/^(psexec|psexec64|wmic|mstsc|sc|schtasks)\.exe$/i OR ParentBaseFileName=/^(PSEXESVC|wmiprvse|wsmprovhost)\.exe$/i) | aid <=> discovery.aid | UserName <=> discovery.UserName} include:[aid,ComputerName,UserName,FileName,CommandLine],
 sequence=true,within=120m)