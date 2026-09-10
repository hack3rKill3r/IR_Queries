// IR-423 - Brute Force Against a Single User
// Purpose: Identify accounts with high failed-logon volume.
// MITRE ATT&CK: T1110.001
#event_simpleName=UserLogonFailed2
| groupBy([UserName],function=[count(as=Failures),count(ComputerName,distinct=true,as=TargetHosts),collect([ClientComputerName,LogonType])],limit=max)
| Failures>=20
| sort(Failures,order=desc)