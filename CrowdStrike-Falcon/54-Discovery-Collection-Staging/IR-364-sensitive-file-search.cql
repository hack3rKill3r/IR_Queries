// IR-364 - Sensitive File Search
#event_simpleName=ProcessRollup2
CommandLine=/(password|credential|secret|wallet|\.kdbx|\.pem|\.pfx|\.ppk|\.rdp|backup|finance|payroll|confidential|private)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)