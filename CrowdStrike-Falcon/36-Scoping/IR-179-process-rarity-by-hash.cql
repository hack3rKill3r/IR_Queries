// IR-179 - Rare Process Hashes Across Estate
// Purpose: Surface executable/hash combinations seen on very few endpoints.
#event_simpleName=ProcessRollup2
| groupBy([FileName,SHA256HashData], function=[count(as=ExecutionCount),count(aid,distinct=true,as=EndpointCount),collect([ComputerName])], limit=max)
| EndpointCount<=2
| sort(ExecutionCount, order=asc)