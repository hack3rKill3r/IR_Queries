// IR-074 - User Endpoint Spread
// Replace COMPROMISED-USER with the account under investigation.
#event_simpleName=ProcessRollup2 UserName="COMPROMISED-USER"
| groupBy([ComputerName], function=[count(as=ExecutionCount), collect([FileName])], limit=max)
| sort(ExecutionCount, order=desc)