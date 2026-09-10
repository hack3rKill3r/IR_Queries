// IR-136 - Failed Logons by User
// Purpose: Rank accounts by failed authentication volume.
#event_simpleName=UserLogonFailed2
| groupBy([UserName], function=[count(as=FailedLogons),count(ComputerName, distinct=true, as=TargetHosts),collect([ClientComputerName,ComputerName,LogonType])], limit=max)
| sort(FailedLogons, order=desc)