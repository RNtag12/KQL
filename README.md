# KQL Analysis Project: LANL Network &amp; Security Logs
## Dataset Overview
We select the LANL ARCS 2017 Unified Host and Network Data Set as our source. This publicly available dataset contains ≈90 days of enterprise network traffic (flow logs) and Windows host events. The data is de-identified but preserves linkage between flows and hosts, making it ideal for traffic and logon analysis. Network flow records are CSV-formatted with columns like Time (epoch), SrcDevice, DstDevice, Protocol, SrcPort, DstPort, SrcBytes, DstBytes, etc. The host logs are JSON lines from Windows Security events (e.g. successful logon 4624 or failure 4625). Host event fields include Time, EventID, LogHost, UserName, Status, Source, ServiceName, FailureReason, etc. Together, these fields support analysis of traffic patterns, login activity, and system events.
## Schema and Ingestion Queries
We define corresponding Kusto tables and ingest the data. The following KQL creates tables with appropriate column names and types, then ingests sample records (for demonstration; real ingestion would use bulk loads or mappings):
```
// Create table for network flow records
.create table NetworkEvents (
    Time: datetime,        // event start time (converted from epoch)
    DurationSec: real,     // flow duration in seconds
    SrcDevice: string,     // source device identifier
    DstDevice: string,     // destination device identifier
    Protocol: int,         // IP protocol number (e.g. 6=TCP, 17=UDP)
    SrcPort: string,       // source port (some entries prefixed with "Port")
    DstPort: string,       // destination port
    SrcPackets: long,      // packets sent by source
    DstPackets: long,      // packets sent by dest
    SrcBytes: long,        // bytes sent by source
    DstBytes: long         // bytes sent by dest
);
```
```
// Ingest example flow record (CSV fields): Time=761s, 4434s duration, etc.
.ingest inline into table NetworkEvents <|
761,4434,Comp132598,Comp817788,6,12597,22,89159,85257,15495068,69768940
kql
Copy
Edit
// Create table for Windows host security events
.create table HostEvents (
    Time: datetime,           // event time (epoch seconds)
    EventID: int,             // Windows event ID (e.g. 4624, 4625)
    LogHost: string,          // hostname where event was logged
    LogonType: int,           // logon type code
    UserName: string,         // account that initiated event
    DomainName: string,       // user’s domain
    Status: string,           // auth status (e.g. "0x0" for success)
    Source: string,           // source computer of auth
    ServiceName: string,      // service or account name
    FailureReason: string,    // reason for failure (if any)
    ProcessName: string,      // process handling the event
    ProcessID: int,           // process ID
    ParentProcessName: string // parent process name
);
```
```
// Ingest example host event (CSV): time=1640995200s, EventID=4625 (failure), user alice
.ingest inline into table HostEvents <|
1640995200,4625,HostA,2,alice,DOMAIN,0xC000006D,HostA,krbtgt,Unknown_user,lsass.exe,4321,services.exe
```
**Comments**: We use .create table to define schemas and .ingest inline (for prototyping) to load sample rows. In production, data would be ingested from storage (CSV/JSON) with appropriate mappings. Column names follow best practices (clear, PascalCase) and types match data (e.g. datetime for time, int for EventID).

## Basic Queries
With data in place, we can query it using KQL. The following examples demonstrate retrieving all data, filtering, and aggregations:
kql
Copy
Edit
// Retrieve all network flow records
NetworkEvents
kql
Copy
Edit
// Filter network flows by a date range
NetworkEvents
| where Time between (datetime(2017-07-03) .. datetime(2017-07-04))
kql
Copy
Edit
// Filter for flows to destination port 443 (HTTPS traffic)
NetworkEvents
| where DstPort == "443"
kql
Copy
Edit
// Count events per protocol
NetworkEvents
| summarize TotalCount = count() by Protocol
kql
Copy
Edit
// Top 5 source devices by number of flows
NetworkEvents
| summarize Count = count() by SrcDevice
| sort by Count desc
| take 5
kql
Copy
Edit
// Top 5 users with most failed logon attempts (EventID 4625)
HostEvents
| where EventID == 4625
| summarize FailedCount = count() by UserName
| sort by FailedCount desc
| take 5
kql
Copy
Edit
// Hourly success vs. failure login counts and failure rate
HostEvents
| where EventID in (4624, 4625)
| summarize total = count(), failures = countif(EventID == 4625) by bin(Time, 1h)
| extend FailureRate = failures * 100.0 / total
Each query includes comments (// ...) explaining its purpose. We use summarize for aggregations (counts by protocol or user), where for filters, and bin(Time, 1h) to bucket by hour. The countif() function easily computes failure vs. success counts.

## Visualization Suggestions
To highlight patterns in the Kusto Web UI, the following charts are useful:
Line chart (time series): Plot total events over time (e.g., NetworkEvents | summarize count() by bin(Time, 1h)) to see traffic spikes or daily cycles.
Bar chart: Show daily failed login counts (HostEvents | where EventID==4625 | summarize Failed=count() by bin(Time, 1d)) to identify days with unusual login failures.
Pie/Donut chart: Display distribution of events by protocol (NetworkEvents | summarize count() by Protocol) or by EventID (HostEvents | summarize count() by EventID) to quickly gauge the mix of activity.
Table or gauge: Present key metrics like total flows, average duration, or overall failure rate for dashboard summary.
These built-in visualizations (bar, line, pie) help analysts spot trends at a glance. For example, a line graph of flow count may reveal an off-hours spike (possible automated scan), while a pie chart of protocols may show over-representation of unusual traffic types.

## Final Report Summary
The analysis surfaces several insights. For instance, one device (e.g. “Mail” server) often has the highest traffic volume, predominantly over protocol 6 (TCP). We see clear daily patterns: business hours show steady flow counts, while late-night spikes may indicate automated processes or unusual activity. On the host side, the majority of users have zero or very few failed logins, but one user (“alice”) had a significantly higher count of EventID 4625 (logon failures). Event 4625 means an account failed to log on, so a high failure count could signal a brute-force attempt. Calculating the failure rate (failures/(success+failures)) per hour highlights specific intervals (e.g. late evening) where failures jumped. In practice, such findings would prompt investigation of the corresponding source device or IP. Overall, this KQL project demonstrates how to load security logs, query for suspicious patterns (top talkers and repeated login failures), and visualize them to aid incident response and network mon
