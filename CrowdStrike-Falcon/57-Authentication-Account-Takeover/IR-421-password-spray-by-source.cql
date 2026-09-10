// IR-421 - Password Spray by Source
// Purpose: Identify a source system attempting failed logons against many users.
// MITRE ATT&CK: T1110.003
#event_simpleName=UserLogonFailed2
ClientComputerName=*
| groupBy([ClientComputerName],function=[count(as=Failures),count(UserName,distinct=true,as=UniqueUsers),collect([ComputerName,UserName,LogonType])],limit=max)
| UniqueUsers>=5
| sort(UniqueUsers,order=desc)