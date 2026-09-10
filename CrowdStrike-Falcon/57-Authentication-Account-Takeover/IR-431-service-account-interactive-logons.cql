// IR-431 - Service Account Interactive/RDP Logons
// Purpose: Surface likely service accounts used interactively.
// Tune naming patterns to your environment.
#event_simpleName=UserLogon
UserName=/(svc|service|sql|backup|app)[-_]?[A-Za-z0-9]*/i
(LogonType=2 OR LogonType=10)
| table([@timestamp,ComputerName,ClientComputerName,UserName,LogonType,UserIsAdmin,AuthenticationPackage],limit=20000)