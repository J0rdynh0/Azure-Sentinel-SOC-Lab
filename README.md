# Azure-Sentinel-SOC-Lab

## Overview

This project demonstrates a full end‑to‑end SOC workflow using Microsoft Sentinel. I deployed a honeypot VM, collected real failed RDP login attempts, enriched attacker IPs with geolocation data, visualized global attack patterns in a custom Sentinel workbook, and created an anomaly‑based detection rule to identify brute‑force behavior.
The result is a complete, real‑world SOC case study that showcases threat detection, log analysis, KQL proficiency, and security monitoring in Azure.

## Objectives

- Deploy a Windows honeypot VM and collect SecurityEvent logs
- Ingest a GeoIP dataset into Sentinel using a watchlist
- Enrich failed RDP login events with geolocation data
- Build a custom Sentinel workbook with a global attack map
- Create an anomaly‑based detection rule for failed logons

## Skills Learned

- Microsoft Sentinel configuration and log ingestion
- KQL (Kusto Query Language) for log analysis and enrichment
- Watchlist creation and IP‑based geolocation lookups
- Workbook design and map visualization
- Threat detection logic and analytics rule creation
- Understanding of RDP brute‑force behavior and attacker patterns
- SOC investigation fundamentals and incident triage

