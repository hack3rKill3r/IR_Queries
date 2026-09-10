// IR-273 - Mass File Write Burst
// Purpose: Identify endpoints with unusually high file-write volume in short intervals.
#event_simpleName=/FileWritten$/
| bucket(span=5m)
| groupBy([ComputerName,_bucket], function=[count(as=FilesWritten),count(TargetFileName,distinct=true,as=UniqueFiles),collect([ContextBaseFileName])], limit=max)
| FilesWritten>1000
| sort(FilesWritten, order=desc)