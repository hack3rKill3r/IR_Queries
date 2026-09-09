// IR-077 - IPv4 Listening Services
// Purpose: Identify processes/endpoints listening on IPv4 ports.
#event_simpleName=NetworkListenIP4
| table([@timestamp,ComputerName,LocalAddressIP4,LocalPort,ContextProcessId], limit=20000)