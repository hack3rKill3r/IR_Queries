// IR-135 - Users Accessing a Host
// Replace VICTIM-HOST with the endpoint under investigation.
#event_simpleName=UserLogon ComputerName="VICTIM-HOST"
| groupBy([UserName], function=[count(as=LogonCount),collect([ClientComputerName,LogonType,AuthenticationPackage])], limit=max)
| sort(LogonCount, order=desc)