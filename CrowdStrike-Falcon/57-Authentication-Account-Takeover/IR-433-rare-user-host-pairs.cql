// IR-433 - Rare User/Host Logon Pairs
// Purpose: Surface account-host combinations with low frequency.
#event_simpleName=UserLogon
| groupBy([UserName,ComputerName],function=[count(as=Logons),collect([ClientComputerName,LogonType,AuthenticationPackage])],limit=max)
| Logons<=2
| sort(Logons,order=asc)