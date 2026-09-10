// IR-160 - NTDS IFM Extraction Indicators
// Purpose: Identify ntdsutil Install From Media workflow strings that can produce an offline AD database copy.
// MITRE ATT&CK: T1003.003
#event_simpleName=ProcessRollup2
CommandLine=/(activate\s+instance\s+ntds|\bifm\b|create\s+full)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)