# Phase 4: Frontend Visualization Specification

This document outlines the required UI components, data structures, and recommended charts for building a SOC-grade incident dashboard based on the output of the NetForensicX pipeline.

The frontend should consume a single file: `incidents_correlated.json`. All metrics and distributions are pre-calculated by the backend.

---

## 1. Global Summary Dashboard (Top KPIs)
At the very top of the page, display the overall health of the network at a glance.

- **JSON Fields**: 
  - `total_high` (Integer)
  - `total_medium` (Integer)
- **UI Component**: **KPI Scorecards**
  - Two large, bold metric cards. 
  - The High Severity card should be styled in a pulsing red or dark crimson.
  - The Medium Severity card should be styled in orange/yellow.

## 2. Network Protocol & Service Distribution
Provides a quick visualization of how the malicious traffic is communicating.

- **JSON Fields**: 
  - `protocol_distribution` (Object: e.g., `{"tcp": 3, "udp": 1}`)
  - `service_distribution` (Object: e.g., `{"http": 2, "dns": 1}`)
- **UI Component**: **Donut Charts / Pie Charts**
  - Render two separate donut charts showing the percentage breakdown of the protocols and services used across all flagged incidents.

## 3. The Attack Chain Visualizer (The "Hero" Component)
Instead of forcing analysts to read text, draw the attack visually.

- **JSON Fields** (From inside `high_severity` array objects):
  - `orig_h` (Source IP)
  - `orig_p` (Source Port)
  - `dns[0].query` or `http[0].host` (Destination Domain)
  - `files` (Array of File Hashes)
- **UI Component**: **Directed Node Graph** (using `React Flow`, `D3.js`, or `Vis.js`)
  - Render a visual map mapping the lateral movement/exfiltration: 
    `[Laptop Icon: Source IP] ➔ [Globe Icon: Domain] ➔ [Document Icon: File Hash]`. 
  - If the file triggered a YARA hit, the document icon should glow red.

## 4. The Incident Triage Table
A sortable data grid allowing analysts to quickly scroll through every generated incident.

- **JSON Fields**:
  - `score` (Integer)
  - `orig_h` & `orig_p` (Source IP and Port)
  - `resp_h` & `resp_p` (Destination IP and Port)
  - `service` or `proto` (e.g., HTTP, DNS, SSL)
- **UI Component**: **Data Grid / Table**
  - Sort the table by `score` descending by default. 
  - Add a visual "Threat Bar" inside the score column (e.g., a score of 1760 fills the bar 100% red).

## 5. Intelligence & Alert Breakdown (Triage Modal)
When a user clicks on a specific incident in the triage table or node graph, a side-panel or modal should slide out displaying exactly *why* this incident is flagged as malicious.

- **JSON Fields**:
  - `intel_hits` (Array of strings, e.g., `"YARA Match (...)"` or `"VT Malicious IP"`)
  - `suricata_alerts` (Array of objects containing `signature` and `severity`)
- **UI Component**:
  - **Radar Chart / Spider Chart**: Shows the distribution of the threat (e.g., is this incident mostly YARA hits, mostly Suricata Network alerts, or mostly Threat Intel IP flags?).
  - **Bullet Point List**: A clean, scrollable list of the exact YARA rule names and Suricata Signatures triggered, formatted with small warning icons (⚠️).
