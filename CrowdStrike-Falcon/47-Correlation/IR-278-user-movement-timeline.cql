// IR-278 - User Movement Timeline
// Replace USERNAME with the account under investigation.
// Purpose: Reconstruct authentication movement across endpoints.
#event_simpleName=UserLogon
UserName="USERNAME"
| table([@timestamp,ClientComputerName,ComputerName,UserName,LogonType,AuthenticationPackage,UserIsAdmin], limit=20000)
| sort(@timestamp, order=asc)