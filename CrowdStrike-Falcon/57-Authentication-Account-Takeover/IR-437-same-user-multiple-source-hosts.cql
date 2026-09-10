// IR-437 - Same User from Multiple Source Hosts
// Purpose: Identify accounts authenticating from many distinct source systems.
#event_simpleName=UserLogon
ClientComputerName=*
| groupBy([UserName],function=[count(as=Logons),count(ClientComputerName,distinct=true,as=SourceHosts),collect([ClientComputerName,ComputerName,LogonType])],limit=max)
| SourceHosts>=3
| sort(SourceHosts,order=desc)