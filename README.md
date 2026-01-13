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

## Environment Setup

1. Create a Resource Group

   - Region: Choose one close to you

<img width="970" height="660" alt="image" src= "https://github.com/J0rdynh0/Azure-Sentinel-SOC-Lab/blob/main/images/Resource%20group.png?raw=true" />

2. Deploy a Windows Honeypot VM

   - This VM will be intentionally exposed to the internet. The Windows firewall was disabled.

<img width= "970" height="760" alt="image" src= "https://github.com/J0rdynh0/Azure-Sentinel-SOC-Lab/blob/main/images/Create%20VM.png?raw=true" />
  
3. Create a new VNet

<img width= "970" height="769" alt="image" src= "https://github.com/J0rdynh0/Azure-Sentinel-SOC-Lab/blob/main/images/Create%20VNET.png?raw=true" />

The Network Security Group (NSG) was configured with an inbound rule allowing RDP (port 3389) from any source. This setup will allow the Honeypot to attract brute-force login attempts from external actors.

<img width= "970" height="769" alt="image" src= "https://github.com/J0rdynh0/Azure-Sentinel-SOC-Lab/blob/main/images/VNET%20settings.png?raw=true" />

## Set up Microsoft Sentinel

I already had a Log Analytic Workspace that I utilized for this lab. However, if you do need to create your own and set up Sentinel, please follow these steps:

1. Create a Log Analytics Workspace

   - In Azure -> select Log Analytic Workspace
   - Region: same as VM
  
2. Enable Sentinel

   - In Azure -> Search "Microsoft Sentinel" -> Create -> Select your workspace
  
3. Connect Data Sources
   In Microsoft Defender:

   - Select Microsoft Sentinel -> Content Management -> Content hub
   - Search and install Windows Security Events. This solution contains the data connector Windows Security Events via AMA
   - Connect your VM
   - You should now see logs flowing into the table 'SecurityEvent'

img
  
  ## How to confirm Logs are Flowing
  Run this KQL query in Sentinel:

  ```kusto
SecurityEvent
| where  TimeGenerated > ago(1h)
| take 20
```

- If you see Event IDs like 4624 and 4625, you're connected.

## Analyze Attacks Using KQL

- Utilized KQL to Query for Failed RDP Login attempts (Event ID = 4625)

<img width= "1000" height="800" alt="image" src= "https://github.com/J0rdynh0/Azure-Sentinel-SOC-Lab/blob/main/images/KQL%20Query%20-%20Microsoft%20Defender.png?raw=true" />

```kusto
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, EventID, Activity, IPAddress
```
- Count Attacks by IP

<img width= "1000" height="800" alt="image" src= "https://github.com/J0rdynh0/Azure-Sentinel-SOC-Lab/blob/main/images/KQL%20Query%20count%20results.png?raw=true" />

 ```kusto
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IpAddress
| order by Attempts desc
```

## Enrich IPs with Geolocation (Watchlist) 

Uploaded a watchlist mapping IPs to geolocation data and joined it with failed login events for enrichment.

<img width= "1000" height="800" alt="image" src= "https://github.com/J0rdynh0/Azure-Sentinel-SOC-Lab/blob/main/images/Mapping%20KQL.png?raw=true" />

```kusto
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == <attacker IP address>
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
| project TimeGenerated, Computer, AttackerIp = IpAddress, cityname, countryname, latitude, longitude
```
## Create an Global Attack Map Workbook

I created a custom workbook and added a map visualization using the enriched dataset. The map plotted attacker locations globally, with bubble size representing the number of failed attempts.

Map configuration included:
- Latitude field: latitude
- Longitude field: longitude
- Metric Value: FailedAttempts
- Metric Label: IpAddress
- Tooltip fields: IpAddress, city, country, count

img

## Results

img 

After nearly 48 hours of my honeypot VM exposed to the internet, I received over 60,000 brute force attempts! A vast majortiy of events came from IPs in Jordansow, Poland and Ranchos, Argentina.

## Create an Anomaly-Based Detection Rule

To operationalize the detection, I built a Sentinel Analytics Rule using a baseline‑and‑threshold model.
Final detection logic:

img

This rule triggers when an attacker exceeds the expected number of failed RDP attempts within a 1‑hour window.

## Conclusion

This project demonstrates a complete SOC workflow:
- 	Real attacker traffic collected from a honeypot
- 	Enriched with geolocation intelligence
- 	Visualized on a global attack map
-  Detected using anomaly‑based logic
- 	Ready for incident investigation and triage

It highlights practical, hands‑on experience with Microsoft Sentinel, KQL, threat detection, and security monitoring 
