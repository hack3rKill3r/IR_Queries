// IR-432 - Administrative Account Host Spread
// Purpose: Identify admin-marked accounts authenticating to many endpoints.
#event_simpleName=UserLogon
UserIsAdmin=1
| groupBy([UserName],function=[count(as=Logons),count(ComputerName,distinct=true,as=Hosts),collect([ComputerName,ClientComputerName,LogonType])],limit=max)
| sort(Hosts,order=desc)