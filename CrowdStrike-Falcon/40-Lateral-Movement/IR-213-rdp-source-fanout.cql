// IR-213 - RDP Source Fan-Out
// Purpose: Identify source systems initiating RDP to many destinations.
#event_simpleName=UserLogon
LogonType=10
ClientComputerName=*
| groupBy([ClientComputerName], function=[count(as=RDPLogons),count(ComputerName,distinct=true,as=DestinationHosts),collect([UserName,ComputerName])], limit=max)
| sort(DestinationHosts, order=desc)