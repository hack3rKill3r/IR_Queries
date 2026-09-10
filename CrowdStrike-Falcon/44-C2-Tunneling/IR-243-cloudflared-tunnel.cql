// IR-243 - Cloudflared Tunnel
// Purpose: Identify cloudflared tunnel usage.
// MITRE ATT&CK: T1572
#event_simpleName=ProcessRollup2
(FileName="cloudflared.exe" OR CommandLine=/cloudflared.*tunnel/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)