// IR-246 - SOCKS Proxy Strings
// Purpose: Identify command lines referencing SOCKS proxying or common proxy tools.
// MITRE ATT&CK: T1090
#event_simpleName=ProcessRollup2
CommandLine=/(socks4|socks5|proxychains|chisel.*(server|client)|ligolo|gost.*-L|gost.*-F)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)