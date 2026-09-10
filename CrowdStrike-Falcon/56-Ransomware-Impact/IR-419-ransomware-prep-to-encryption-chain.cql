// IR-419 - Ransomware Preparation -> Encryption Chain
// Purpose: Correlate destructive preparation with subsequent heavy file writes on the same endpoint.
// MITRE ATT&CK: T1490 / T1486
correlate(
 prep:{
   #event_simpleName=ProcessRollup2
   CommandLine=/(delete.*shadows|shadowcopy.*delete|delete.*catalog|recoveryenabled.*no|ignoreallfailures|sc.*stop|net.*stop)/i
 } include:[aid,ComputerName,UserName,TargetProcessId,FileName,CommandLine],
 impact:{
   #event_simpleName=/FileWritten$/
   | aid <=> prep.aid
 } include:[aid,ComputerName,ContextBaseFileName,TargetFileName],
 sequence=true,
 within=30m
)