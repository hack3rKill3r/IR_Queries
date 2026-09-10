// IR-137 - Failed Logons by Host
// Purpose: Rank endpoints by failed authentication volume.
#event_simpleName=UserLogonFailed2
| groupBy([ComputerName], function=[count(as=FailedLogons),count(UserName, distinct=true, as=UniqueUsers),collect([UserName,ClientComputerName,LogonType])], limit=max)
| sort(FailedLogons, order=desc)