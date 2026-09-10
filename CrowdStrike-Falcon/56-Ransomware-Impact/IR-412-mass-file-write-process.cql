// IR-412 - Mass File Writes by Process
// Purpose: Identify a process responsible for unusually high write volume.
// MITRE ATT&CK: T1486
#event_simpleName=/FileWritten$/
ContextBaseFileName=*
| bucket(span=5m)
| groupBy([ComputerName,ContextBaseFileName,ContextProcessId,_bucket],function=[count(as=Writes),count(TargetFileName,distinct=true,as=UniqueFiles)],limit=max)
| Writes>1000
| sort(Writes,order=desc)