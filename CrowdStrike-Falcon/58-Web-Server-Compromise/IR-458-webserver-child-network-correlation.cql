// IR-458 - Web Server Child Process + Network Correlation
// Purpose: Correlate suspicious child execution with network activity.
(
 #event_simpleName=ProcessRollup2
 OR #event_simpleName=NetworkConnectIP4
)
| falconPID:=TargetProcessId
| falconPID:=ContextProcessId
| selfJoinFilter(field=[aid,falconPID],where=[
 {#event_simpleName=ProcessRollup2 ParentBaseFileName=/(w3wp|httpd|apache2|nginx|php-fpm|php-cgi|java)(\.exe)?$/i},
 {#event_simpleName=NetworkConnectIP4}
])
| groupBy([aid,falconPID],function=[collect([ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,RemoteAddressIP4,RemotePort])],limit=max)