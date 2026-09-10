// IR-248 - Ligolo-ng Execution
// Purpose: Identify Ligolo agent/proxy execution.
// MITRE ATT&CK: T1572
#event_simpleName=ProcessRollup2
(FileName=/(ligolo|proxy|agent)\.exe$/i AND CommandLine=/(ligolo|connect|proxy|agent)/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)