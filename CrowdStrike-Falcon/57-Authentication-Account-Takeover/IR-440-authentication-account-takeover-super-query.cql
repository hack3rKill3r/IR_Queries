// IR-440 - Authentication / Account Takeover Super Query
// Purpose: Broad first-pass authentication hunt for spray, brute force, RDP, explicit credentials, admin use, and lateral spread.
#event_simpleName=/UserLogon/
| case {
  #event_simpleName=UserLogonFailed2 | Outcome:="failure";
  #event_simpleName=UserLogon | Outcome:="success";
}
| groupBy([UserName,ComputerName,ClientComputerName,LogonType,AuthenticationPackage,UserIsAdmin,Outcome],function=[count(as=Events)],limit=max)
| sort(Events,order=desc)