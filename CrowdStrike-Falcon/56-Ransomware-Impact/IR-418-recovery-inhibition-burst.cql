// IR-418 - Recovery Inhibition Burst
// Purpose: Identify multiple recovery-inhibition tools/commands on one host in a short window.
// MITRE ATT&CK: T1490
#event_simpleName=ProcessRollup2
(
 FileName=/^(vssadmin|wbadmin|bcdedit|wmic|reagentc)\.exe$/i
 OR CommandLine=/(delete.*shadows|shadowcopy.*delete|delete.*catalog|recoveryenabled.*no|ignoreallfailures|reagentc.*disable)/i
)
| bucket(span=10m)
| groupBy([ComputerName,UserName,_bucket],function=[count(as=Events),count(FileName,distinct=true,as=UniqueTools),collect([FileName,CommandLine])],limit=max)
| UniqueTools>=2
| sort(Events,order=desc)