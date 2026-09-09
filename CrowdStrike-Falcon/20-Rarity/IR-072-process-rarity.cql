// IR-072 - Process Rarity
// Purpose: Rank executable names by execution and endpoint prevalence for outlier hunting.
#event_simpleName=ProcessRollup2
| groupBy([FileName], function=[count(as=ExecutionCount), count(aid, distinct=true, as=EndpointCount), collect([ComputerName])], limit=max)
| sort(EndpointCount, order=asc)