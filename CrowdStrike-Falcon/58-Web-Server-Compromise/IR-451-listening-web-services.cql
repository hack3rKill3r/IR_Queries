// IR-451 - Listening Web Services
// Purpose: Identify endpoints listening on common web ports for exposure scoping.
#event_simpleName=NetworkListenIP4
(LocalPort=80 OR LocalPort=443 OR LocalPort=8080 OR LocalPort=8443 OR LocalPort=8000 OR LocalPort=8888)
| table([@timestamp,ComputerName,LocalAddressIP4,LocalPort,ContextProcessId],limit=20000)