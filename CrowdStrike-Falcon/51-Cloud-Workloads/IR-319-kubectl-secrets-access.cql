// IR-319 - kubectl Secret Access
// Purpose: Identify commands retrieving Kubernetes Secrets.
#event_simpleName=ProcessRollup2
FileName=/^kubectl$/i
CommandLine=/\b(get|describe)\b.*\bsecrets?\b/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)