Splunk Query for VPN SSL Brute Force Alert
This query is designed to detect potential security incidents in firewall logs, specifically focusing on VPN SSL login failures. By filtering out SSL login failure events, it analyzes the data to identify patterns of repeated failures that could indicate brute force attacks, unauthorized access attempts, or other malicious activities. The query highlights source IP addresses that appear multiple times, helping identify potential attackers or misconfigurations.
### Query:

index="*" sourcetype="yoursourcetype" ssl-login-fail
| stats count by remip, msg
| where count > 40
| rename remip as "Source IP", msg as "Message", count as "Failed Login Attempts"
| table "Source IP", "Message", "Failed Login Attempts"
