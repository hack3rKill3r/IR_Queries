// IR-420 - Ransomware Impact Super Query
// Purpose: Broad first-pass hunt for recovery inhibition, service/process disruption, lateral deployment, and encryption-related write bursts.
(
 #event_simpleName=ProcessRollup2
 (
  CommandLine=/(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|wbadmin.*delete.*catalog|bcdedit.*recoveryenabled.*no|bcdedit.*ignoreallfailures|reagentc.*disable)/i
  OR
  (FileName=/^(sc|net|net1|taskkill)\.exe$/i CommandLine=/(stop|delete|veeam|backup|sql|exchange|oracle|vmware)/i)
  OR
  (FileName=/^(psexec|psexec64|wmic|schtasks)\.exe$/i CommandLine=/(\\\\|\/node:|\/create|process\s+call\s+create)/i)
 )
)
OR
(
 #event_simpleName=/FileWritten$/
 TargetFileName=/(README|RECOVER|RESTORE|DECRYPT|HOW_TO|RANSOM)/i
)
| table([@timestamp,#event_simpleName,ComputerName,UserName,ParentBaseFileName,ContextBaseFileName,FileName,CommandLine,TargetFileName,FilePath,SHA256HashData],limit=20000)