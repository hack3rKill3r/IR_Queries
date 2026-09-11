// IR-452 - High-Risk Listening Ports
// Purpose: Identify listeners on commonly abused management/service ports.
#event_simpleName=NetworkListenIP4
LocalPort=/^(21|22|23|135|139|445|3389|5985|5986|5900|8080|8443)$/
| table([@timestamp,ComputerName,LocalAddressIP4,LocalPort,ContextProcessId],limit=20000)