// IR-194 - MSIExec Remote Package
// Purpose: Identify msiexec loading an MSI over HTTP/HTTPS.
// MITRE ATT&CK: T1218.007
#event_simpleName=ProcessRollup2
FileName="msiexec.exe"
CommandLine=/https?:\/\//i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData], limit=20000)