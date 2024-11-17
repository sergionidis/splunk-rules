# Splunk Query for Firewall IPS Alert

This query is designed to detect potential security events from firewall logs, specifically filtering out IPS (Intrusion Prevention System) events and analyzing the data for unusual behavior. It focuses on events that occur multiple times,
 which could indicate a larger security issue or malicious activity.
### Query:

```spl
index="*" sourcetype="yoursourcetype" subtype="ips" | rename "action" as "Action", "attack" as "Atttack", "level" as "Severity", "devname" as "Firewall", "dstip" as "Destination IP", "dstport" as "Destination Port", "msg" as "Info", "srcip" as "Source IP"
| table _time, "Action", "Severity", "Attack", "Firewall", "Info", "Source IP", "Destination IP", "Destination Port"
| stats count by "Source IP", "Info", "Ataque", "Action", "Puerto Destino"
| sort -count
| where count >= 10