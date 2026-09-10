// IR-426 - RDP Source Fan-Out
// Purpose: Identify source systems authenticating to many RDP destinations.
// MITRE ATT&CK: T1021.001
#event_simpleName=UserLogon
LogonType=10
ClientComputerName=*
| groupBy([ClientComputerName],function=[count(as=RDPLogons),count(ComputerName,distinct=true,as=DestinationHosts),count(UserName,distinct=true,as=Users),collect([ComputerName,UserName])],limit=max)
| DestinationHosts>=3
| sort(DestinationHosts,order=desc)