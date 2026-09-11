// IR-459 - Externally Exposed Service Listener Candidates
// Purpose: Review services bound to all interfaces on common remote-management/web ports.
#event_simpleName=NetworkListenIP4
LocalAddressIP4=/^(0\.0\.0\.0|::)?$/
LocalPort=/^(22|80|443|445|3389|5900|5985|5986|8080|8443)$/
| table([@timestamp,ComputerName,LocalAddressIP4,LocalPort,ContextProcessId],limit=20000)