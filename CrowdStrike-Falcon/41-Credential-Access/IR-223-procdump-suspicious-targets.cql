// IR-223 - ProcDump Suspicious Targets
// Purpose: Identify ProcDump activity targeting LSASS or other sensitive processes.
// MITRE ATT&CK: T1003.001
#event_simpleName=ProcessRollup2
FileName=/^procdump(64)?\.exe$/i
CommandLine=/(lsass|winlogon|samss)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData], limit=20000)