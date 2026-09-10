// IR-411 - Ransom Note Spread
// Purpose: Identify repeated ransom-note-like writes across a host.
// MITRE ATT&CK: T1486
#event_simpleName=/FileWritten$/
TargetFileName=/(README|RECOVER|RESTORE|DECRYPT|HOW_TO|RANSOM)/i
| groupBy([ComputerName],function=[count(as=NoteWrites),count(TargetFileName,distinct=true,as=UniqueNotes),collect([TargetFileName,FilePath,ContextBaseFileName])],limit=max)
| sort(NoteWrites,order=desc)