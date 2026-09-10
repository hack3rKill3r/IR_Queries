// IR-178 - Same Command-Line Pattern Across Estate
// Replace SEARCH_STRING with an escaped search term or regex.
#event_simpleName=ProcessRollup2
CommandLine=/SEARCH_STRING/i
| groupBy([ComputerName,UserName], function=[count(as=Executions),collect([FileName,CommandLine])], limit=max)
| sort(Executions, order=desc)