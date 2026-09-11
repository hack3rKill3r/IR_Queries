// IR-457 - Rare Web Server Child Processes
// Purpose: Rank child processes spawned by web-server workers by prevalence.
#event_simpleName=ProcessRollup2
ParentBaseFileName=/(w3wp|httpd|apache2|nginx|php-fpm|php-cgi|java)(\.exe)?$/i
| groupBy([ParentBaseFileName,FileName],function=[count(as=Executions),count(aid,distinct=true,as=Endpoints),collect([ComputerName,CommandLine])],limit=max)
| sort(Endpoints,order=asc)