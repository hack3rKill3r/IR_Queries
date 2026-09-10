// IR-140 - Estate-Wide RDP Logons
// Purpose: Scope RDP activity by account and endpoint across the estate.
#event_simpleName=UserLogon LogonType=10
| groupBy([UserName,ComputerName], function=[count(as=RDPLogons),collect([ClientComputerName,AuthenticationPackage,UserIsAdmin])], limit=max)
| sort(RDPLogons, order=desc)