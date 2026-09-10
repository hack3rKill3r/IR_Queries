// IR-245 - Plink Execution
// Purpose: Identify PuTTY Plink usage for remote access, forwarding, or tunneling.
// MITRE ATT&CK: T1021.004 / T1572
#event_simpleName=ProcessRollup2
FileName="plink.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)