// IR-237 - DCSync Tool Strings
// Purpose: Identify common command-line indicators associated with DCSync-capable tooling.
// MITRE ATT&CK: T1003.006
#event_simpleName=ProcessRollup2
CommandLine=/(dcsync|lsadump::dcsync|secretsdump.*just-dc|drsuapi)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)