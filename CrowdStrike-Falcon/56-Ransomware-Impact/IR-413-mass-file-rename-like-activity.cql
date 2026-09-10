// IR-413 - Mass File Rename/Rewrite Heuristic
// Purpose: Use file-write bursts as a proxy for rapid rename/rewrite behavior where rename telemetry is unavailable.
#event_simpleName=/FileWritten$/
| bucket(span=2m)
| groupBy([ComputerName,ContextBaseFileName,_bucket],function=[count(as=Writes),count(TargetFileName,distinct=true,as=UniqueFiles)],limit=max)
| UniqueFiles>500
| sort(UniqueFiles,order=desc)