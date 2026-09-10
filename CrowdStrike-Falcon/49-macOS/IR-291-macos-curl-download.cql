// IR-291 - macOS curl Download
// Purpose: Identify curl-based payload retrieval on macOS.
// MITRE ATT&CK: T1105
event_platform=Mac
#event_simpleName=ProcessRollup2
FileName="curl"
CommandLine=/https?:\/\//i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData], limit=20000)