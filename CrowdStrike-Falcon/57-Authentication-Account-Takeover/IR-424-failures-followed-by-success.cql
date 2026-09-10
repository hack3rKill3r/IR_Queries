// IR-424 - Failed Logons Followed by Success
// Purpose: Compare failures and successes for the same account/host.
// MITRE ATT&CK: T1110
#event_simpleName=/UserLogon/
| case {
  #event_simpleName=UserLogonFailed2 | Failed:=1;
  #event_simpleName=UserLogon | Successful:=1;
}
| groupBy([UserName,ComputerName],function=[sum(Failed,as=Failures),sum(Successful,as=Successes),collect([ClientComputerName,LogonType])],limit=max)
| Failures>3
| Successes>0
| sort(Failures,order=desc)