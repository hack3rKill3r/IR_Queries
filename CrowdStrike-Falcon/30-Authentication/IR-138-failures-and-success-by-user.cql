// IR-138 - Failed and Successful Logons by User
// Purpose: Compare failed and successful authentication events for brute-force/password-spray follow-up.
#event_simpleName=/UserLogon/
| groupBy([UserName,#event_simpleName], function=[count(as=EventCount),count(ComputerName, distinct=true, as=HostCount),collect([ComputerName,ClientComputerName,LogonType])], limit=max)
| sort(EventCount, order=desc)