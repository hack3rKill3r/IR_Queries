// IR-151 - SharpHound Collection Indicators
// Purpose: Identify SharpHound collection activity by common strings and switches.
// MITRE ATT&CK: T1087.002 / T1069.002
#event_simpleName=ProcessRollup2
(FileName=/sharphound/i OR CommandLine=/(SharpHound|CollectionMethod|LoopDuration|Stealth|LDAPUser|LDAPPass)/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)