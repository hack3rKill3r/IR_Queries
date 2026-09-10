// IR-439 - Identity to Endpoint Pivot
// Replace USERNAME with the suspected compromised account.
// Purpose: Scope hosts authenticated to by the user and processes executed under that identity.
(
  (#event_simpleName=UserLogon UserName="USERNAME")
  OR
  (#event_simpleName=ProcessRollup2 UserName="USERNAME")
)
| groupBy([ComputerName],function=[count(as=Events),collect([@timestamp,#event_simpleName,ClientComputerName,LogonType,ParentBaseFileName,FileName,CommandLine])],limit=max)
| sort(Events,order=desc)