// IR-176 - Mass Service Stop/Delete Commands
// Purpose: Find hosts/users issuing large numbers of service stop/delete operations.
// MITRE ATT&CK: T1489
#event_simpleName=ProcessRollup2
FileName=/^(net|net1|sc)\.exe$/i
CommandLine=/(stop|delete)/i
| groupBy([ComputerName,UserName], function=[count(as=ServiceCommands),collect([CommandLine])], limit=max)
| sort(ServiceCommands, order=desc)