// IR-430 - Network Logon Fan-Out
// Purpose: Identify accounts making network logons across many hosts.
// Windows LogonType 3 = Network.
#event_simpleName=UserLogon
LogonType=3
| groupBy([UserName],function=[count(as=NetworkLogons),count(ComputerName,distinct=true,as=DestinationHosts),collect([ComputerName,ClientComputerName,AuthenticationPackage])],limit=max)
| DestinationHosts>=5
| sort(DestinationHosts,order=desc)