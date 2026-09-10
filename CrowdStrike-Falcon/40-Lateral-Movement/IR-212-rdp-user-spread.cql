// IR-212 - RDP User Spread
// Purpose: Show how many hosts each account accessed using RDP.
#event_simpleName=UserLogon
LogonType=10
| groupBy([UserName], function=[count(as=RDPLogons),count(ComputerName,distinct=true,as=DestinationHosts),collect([ComputerName,ClientComputerName])], limit=max)
| sort(DestinationHosts, order=desc)