// IR-427 - RDP User Fan-Out
// Purpose: Identify accounts using RDP across many endpoints.
// MITRE ATT&CK: T1021.001
#event_simpleName=UserLogon
LogonType=10
| groupBy([UserName],function=[count(as=RDPLogons),count(ComputerName,distinct=true,as=DestinationHosts),collect([ComputerName,ClientComputerName])],limit=max)
| DestinationHosts>=3
| sort(DestinationHosts,order=desc)