// IR-438 - User Authentication + Process Timeline
// Replace USERNAME with the account under investigation.
(
  (#event_simpleName=UserLogon UserName="USERNAME")
  OR
  (#event_simpleName=UserLogonFailed2 UserName="USERNAME")
  OR
  (#event_simpleName=ProcessRollup2 UserName="USERNAME")
)
| table([@timestamp,#event_simpleName,ComputerName,ClientComputerName,UserName,LogonType,AuthenticationPackage,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)
| sort(@timestamp,order=asc)