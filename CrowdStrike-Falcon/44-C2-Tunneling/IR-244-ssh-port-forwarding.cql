// IR-244 - SSH Port Forwarding
// Purpose: Identify SSH local, remote, or dynamic port forwarding.
// MITRE ATT&CK: T1572
#event_simpleName=ProcessRollup2
FileName=/^(ssh|plink)\.exe$/i
CommandLine=/(\s-L\s|\s-R\s|\s-D\s)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)