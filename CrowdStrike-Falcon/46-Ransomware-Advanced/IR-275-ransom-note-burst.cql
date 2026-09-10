// IR-275 - Ransom Note Write Burst
// Purpose: Identify repeated creation of ransom-note-like filenames across an endpoint.
#event_simpleName=/FileWritten$/
TargetFileName=/(README|RECOVER|RESTORE|DECRYPT|HOW_TO|RANSOM)/i
| groupBy([ComputerName,TargetFileName], function=[count(as=Writes),collect([@timestamp,ContextBaseFileName,FilePath])], limit=max)
| sort(Writes, order=desc)