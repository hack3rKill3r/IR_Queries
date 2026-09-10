// IR-279 - Multi-Host Attack Path by User
// Replace USERNAME with the suspected compromised account.
// Purpose: Scope hosts touched by the same user and collect related process activity.
(
  (#event_simpleName=UserLogon UserName="USERNAME")
  OR
  (#event_simpleName=ProcessRollup2 UserName="USERNAME")
)
| table([@timestamp,#event_simpleName,ComputerName,ClientComputerName,UserName,LogonType,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)
| sort(@timestamp, order=asc)