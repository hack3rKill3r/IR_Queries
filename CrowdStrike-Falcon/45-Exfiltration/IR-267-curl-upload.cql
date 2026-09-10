// IR-267 - Curl Upload Activity
// Purpose: Identify curl command lines using upload/form-data semantics.
// MITRE ATT&CK: T1048
#event_simpleName=ProcessRollup2
FileName="curl.exe"
CommandLine=/(--upload-file|-T\s|-F\s|--form)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)