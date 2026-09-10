// IR-230 - DPAPI Command-Line References
// Purpose: Hunt for process command lines referencing DPAPI, master keys, or Protect/Unprotect operations.
// MITRE ATT&CK: T1555
#event_simpleName=ProcessRollup2
CommandLine=/(DPAPI|CryptUnprotectData|MasterKey|Protect-CmsMessage|mimikatz.*dpapi)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)