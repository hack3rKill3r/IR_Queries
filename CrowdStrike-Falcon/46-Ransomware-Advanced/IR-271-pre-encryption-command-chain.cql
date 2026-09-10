// IR-271 - Pre-Encryption Command Chain
// Purpose: Hunt for common ransomware preparation commands on the same host.
#event_simpleName=ProcessRollup2
CommandLine=/(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|wbadmin.*delete.*catalog|bcdedit.*recoveryenabled.*no|bcdedit.*ignoreallfailures|sc.*stop|net.*stop)/i
| groupBy([ComputerName,UserName], function=[count(as=PrepCommands),collect([@timestamp,FileName,CommandLine])], limit=max)
| sort(PrepCommands, order=desc)