// IR-272 - Ransomware Tool Burst
// Purpose: Surface hosts rapidly executing multiple destructive/recovery-related utilities.
#event_simpleName=ProcessRollup2
FileName=/^(vssadmin|wbadmin|bcdedit|wmic|sc|net|net1|cipher)\.exe$/i
| bucket(span=10m)
| groupBy([ComputerName,_bucket], function=[count(as=ToolExecutions),count(FileName,distinct=true,as=UniqueTools),collect([FileName,CommandLine,UserName])], limit=max)
| UniqueTools>=3
| sort(ToolExecutions, order=desc)