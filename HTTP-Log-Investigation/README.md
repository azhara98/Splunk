# HTTP Log Investigation – Splunk

## 1. Project Overview

This project focuses on investigating HTTP logs in Splunk to identify and analyze suspicious web activity. It follows a SOC investigation workflow involving log analysis, field extraction, suspicious activity identification, and investigation of potential web-based attacks.

## 2. Threat Context & Use Case

HTTP logs can provide valuable visibility into web-based activity, including reconnaissance, directory enumeration, brute-force activity, and malicious HTTP requests. This project focuses on using Splunk to investigate such activity and identify potentially suspicious sources and requests.

## 3. Data Source & Log Ingestion

HTTP log dataset

Logs were ingested into Splunk for investigation and analysis.

The logs contain HTTP-related information including:

- Source IP
- Destination IP
- Source and destination ports
- HTTP method
- Host
- URI
- User agent
- Request and response information
- HTTP status code
- Security-related tags

## 4. Field Extraction & Data Normalization

Relevant fields were extracted from the raw HTTP logs using Splunk SPL and regular expressions.

Key fields extracted include:

- `src_ip` – Source IP address
- `src_port` – Source port
- `dest_ip` – Destination IP address
- `dest_port` – Destination port
- `method` – HTTP request method
- `host` – HTTP host
- `uri` – Requested URI
- `user_agent` – User-agent information
- `status_code` – HTTP response status code
- `tags` – Security-related event tags

This made the raw HTTP data easier to search, filter, and investigate.

## 5. Baseline Analysis & Visibility

Initial analysis was performed to understand HTTP activity and identify unusual patterns.

The investigation included:

- Analyzing HTTP event volume
- Identifying source IP activity
- Reviewing unique requested URIs
- Identifying frequently targeted destinations
- Reviewing HTTP requests associated with suspicious activity

## 6. Suspicious Web Activity Investigation

Multiple suspicious HTTP activities were investigated using SPL queries.

The investigation included:

- Directory brute-force activity
- Web enumeration activity
- SQL injection-related HTTP events
- High-volume HTTP requests
- Suspicious source IP activity

## 7. Directory Brute-Force Investigation

HTTP activity associated with directory brute-force behavior was analyzed to identify high-volume request sources and the number of unique URIs requested.

Source IP `192.168.203.63` was investigated as part of this analysis.

## 8. Web Enumeration Investigation

Web enumeration activity was analyzed by examining the number of HTTP events, targeted destinations, and unique URIs associated with a source.

Source IP `192.168.202.79` was investigated as part of this analysis.

## 9. SQL Injection Investigation

HTTP events containing SQL injection-related tags were investigated to identify potentially malicious URI requests.

Source IP `192.168.202.110` was analyzed for events tagged with:

`HTTP::URI_SQLI`

## 10. Investigation & Analysis

The extracted fields and SPL queries were used to investigate suspicious HTTP activity.

The investigation focused on:

- Source IP identification
- Request volume
- Unique URI analysis
- Destination analysis
- Suspicious HTTP request patterns
- SQL injection-related events

## 11. Supporting SPL Queries

The SPL queries used during the investigation are documented separately in:

**`splunk_queries.md`**

This file contains the queries used for field extraction and HTTP security investigations.
