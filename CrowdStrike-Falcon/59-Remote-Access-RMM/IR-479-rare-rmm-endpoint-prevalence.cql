// IR-479 - Rare RMM Endpoint Prevalence
// Purpose: Rank remote-access software by endpoint prevalence to identify unusual deployments.
#event_simpleName=ProcessRollup2
FileName=/(AnyDesk|TeamViewer|ScreenConnect|Splashtop|Atera|RustDesk|meshagent|SimpleHelp|rutserv|Supremo|DWAgent|Ninja|Kaseya|Syncro)/i
| groupBy([FileName],function=[count(as=Executions),count(aid,distinct=true,as=Endpoints),collect([ComputerName,FilePath,UserName])],limit=max)
| sort(Endpoints,order=asc)