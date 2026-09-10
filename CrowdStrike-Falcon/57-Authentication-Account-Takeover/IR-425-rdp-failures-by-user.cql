// IR-425 - RDP Failed Logons by User
// Windows LogonType 10 = RemoteInteractive.
#event_simpleName=UserLogonFailed2
LogonType=10
| groupBy([UserName],function=[count(as=Failures),count(ComputerName,distinct=true,as=Hosts),collect([ComputerName,ClientComputerName])],limit=max)
| sort(Failures,order=desc)