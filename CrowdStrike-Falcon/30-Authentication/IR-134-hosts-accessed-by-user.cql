// IR-134 - Hosts Accessed by a User
// Replace COMPROMISED-USER with the account under investigation.
#event_simpleName=UserLogon UserName="COMPROMISED-USER"
| groupBy([ComputerName], function=[count(as=LogonCount),collect([ClientComputerName,LogonType,AuthenticationPackage])], limit=max)
| sort(LogonCount, order=desc)