// IR-283 - Linux Base64 Decode
// Purpose: Identify base64 decoding frequently used for payload deobfuscation.
// MITRE ATT&CK: T1140
event_platform=Lin
#event_simpleName=ProcessRollup2
FileName="base64"
CommandLine=/(-d|--decode)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)