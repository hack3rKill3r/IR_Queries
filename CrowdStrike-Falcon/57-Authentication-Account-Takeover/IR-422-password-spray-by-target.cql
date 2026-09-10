// IR-422 - Password Spray by Target Host
// Purpose: Identify hosts receiving failed logons for many distinct users.
// MITRE ATT&CK: T1110.003
#event_simpleName=UserLogonFailed2
| groupBy([ComputerName],function=[count(as=Failures),count(UserName,distinct=true,as=UniqueUsers),collect([ClientComputerName,UserName,LogonType])],limit=max)
| UniqueUsers>=5
| sort(UniqueUsers,order=desc)