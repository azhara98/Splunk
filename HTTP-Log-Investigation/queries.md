
HTTP Log Investigation – Splunk
Author: Azhara

Description:
This file contains the SPL queries used across the HTTP log
investigation workflow for identifying and analyzing suspicious
web activity.
============================================================


============================================================
1. DirBuster Directory Brute-Force Investigation
Purpose:
Identify high-volume HTTP activity and the number of unique
URIs requested by each source IP.
============================================================

index=main sourcetype="http logs"
| rex field=_raw "^(?<ts>[^\t]+)\t(?<uid>[^\t]+)\t(?<src_ip>[^\t]+)\t(?<src_port>[^\t]+)\t(?<dest_ip>[^\t]+)\t(?<dest_port>[^\t]+)\t(?<trans_depth>[^\t]+)\t(?<method>[^\t]+)\t(?<host>[^\t]+)\t(?<uri>[^\t]+)\t(?<referrer>[^\t]+)\t(?<user_agent>[^\t]+)\t(?<req_len>[^\t]+)\t(?<resp_len>[^\t]+)\t(?<status_code>[^\t]+)\t(?<status_msg>[^\t]+)\t(?<info_code>[^\t]+)\t(?<info_msg>[^\t]+)\t(?<filename>[^\t]+)\t(?<tags>[^\t]+)\t(?<username>[^\t]+)\t(?<password>[^\t]+)"
| stats count as events, dc(uri) as unique_uris by src_ip
| sort -events
============================================================
2. SQL Injection Investigation
Purpose:
Identify SQL injection-related HTTP requests from the specified
source IP and review the requested URIs.
============================================================

index=main sourcetype="http logs"
| rex field=_raw "^(?<ts>[^\t]+)\t(?<uid>[^\t]+)\t(?<src_ip>[^\t]+)\t(?<src_port>[^\t]+)\t(?<dest_ip>[^\t]+)\t(?<dest_port>[^\t]+)\t(?<trans_depth>[^\t]+)\t(?<method>[^\t]+)\t(?<host>[^\t]+)\t(?<uri>[^\t]+)\t(?<referrer>[^\t]+)\t(?<user_agent>[^\t]+)\t(?<req_len>[^\t]+)\t(?<resp_len>[^\t]+)\t(?<status_code>[^\t]+)\t(?<status_msg>[^\t]+)\t(?<info_code>[^\t]+)\t(?<info_msg>[^\t]+)\t(?<filename>[^\t]+)\t(?<tags>[^\t]+)\t(?<username>[^\t]+)\t(?<password>[^\t]+)"
| search tags="HTTP::URI_SQLI" src_ip="192.168.202.110"
| table _time, uri
| head 20
============================================================
3. Path Traversal Investigation
Purpose:
Identify HTTP requests containing path traversal patterns and
review the associated request URI and response status.
============================================================

index=main sourcetype="http logs"
| rex field=_raw "^(?<ts>[^\t]+)\t(?<uid>[^\t]+)\t(?<src_ip>[^\t]+)\t(?<src_port>[^\t]+)\t(?<dest_ip>[^\t]+)\t(?<dest_port>[^\t]+)\t(?<trans_depth>[^\t]+)\t(?<method>[^\t]+)\t(?<host>[^\t]+)\t(?<uri>[^\t]+)\t(?<referrer>[^\t]+)\t(?<user_agent>[^\t]+)\t(?<req_len>[^\t]+)\t(?<resp_len>[^\t]+)\t(?<status_code>[^\t]+)\t(?<status_msg>[^\t]+)\t(?<info_code>[^\t]+)\t(?<info_msg>[^\t]+)\t(?<filename>[^\t]+)\t(?<tags>[^\t]+)\t(?<username>[^\t]+)\t(?<password>[^\t]+)"
| where match(uri, "\.\./") OR match(uri, "etc/passwd") OR match(uri, "boot\.ini")
| search src_ip="192.168.202.79"
| table _time, uri, status_code
| head 20
