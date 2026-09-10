// IR-231 - Browser Login Data References
// Purpose: Identify processes referencing Chromium-style credential stores.
// MITRE ATT&CK: T1555.003
#event_simpleName=ProcessRollup2
CommandLine=/(\\User Data\\.*\\Login Data|\\Default\\Login Data|Local State)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)