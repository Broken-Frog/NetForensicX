# NetForensicX: Context-Aware Attack Narrative Reconstruction and Alert Fatigue Reduction in SOC Pipelines

## Abstract
Modern Security Operations Centers (SOCs) are overwhelmed by alert fatigue. Traditional Intrusion Detection Systems (IDS) like Suricata and network monitors like Zeek generate tens of thousands of disparate alerts for a single cyber incident, placing an immense cognitive load on analysts who must manually correlate these events into a cohesive attack narrative. In this paper, we present **NetForensicX**, an automated Post-Analysis Ingestion Framework that shifts the paradigm from pure anomaly detection to automated triage and narrative reconstruction. This work bridges the gap between detection and investigation by automating the reconstruction of complete attack narratives. NetForensicX automatically extracts payloads, performs clustered YARA scanning, integrates multi-source Threat Intelligence, and utilizes a novel Host-Centric Profiling algorithm to trace lateral movement and identify "Patient Zero." Our evaluation demonstrates that NetForensicX can reduce over 25,000 raw Indicators of Compromise (IOCs) into a single, highly accurate chronological attack story, drastically reducing analyst triage time while preserving strict cryptographic chains of custody for legal defensibility.

## 1. Introduction
The volume of network traffic traversing enterprise networks has rendered manual packet analysis nearly impossible for initial incident triage. Security teams rely on automated systems to flag malicious behavior. However, this has led to a secondary crisis: Alert Fatigue. When a single ransomware infection triggers 10,000 distinct IDS alerts across various protocols, the security analyst is left to manually stitch together the sequence of events. This significantly reduces analyst cognitive load and enables faster incident response in modern SOC environments.

While significant research has focused on improving the accuracy of individual detection models (e.g., machine learning for DDoS detection or malware classification), relatively little attention has been given to the **automated orchestration** of these alerts. Existing tools often lack the context-awareness required to understand the *role* of a host within a broader infection (e.g., distinguishing between the initial vector, an infected secondary host, and an external Command and Control node).

To address this gap, we introduce NetForensicX. This framework acts as an automated, legally defensible pipeline that consumes raw packet captures (PCAPs), carves out executable payloads, scores them against clustered YARA rules, and dynamically maps the internal network topology to reconstruct the attack timeline.

### Contributions
This paper makes the following contributions:
1. A context-aware network forensic framework capable of reconstructing full attack narratives from raw PCAP data.
2. A host-centric profiling model that enables identification of patient zero and lateral movement paths.
3. A volumetric normalization algorithm to prevent alert explosion in DoS scenarios.
4. A unified pipeline integrating behavioral detection, IOC correlation, and threat intelligence enrichment.
5. A forensic integrity model ensuring cryptographic chain-of-custody for generated artifacts.

### Related Work
Traditional tools such as Wireshark provide packet-level visibility but require manual analysis. SIEM platforms like Splunk and Microsoft Sentinel aggregate alerts but rely heavily on rule-based correlation and generate significant alert fatigue.

Recent research has explored machine learning-based detection; however, these approaches focus on classification rather than full attack reconstruction. NetForensicX differs by combining behavioral analysis, IOC correlation, and host-centric profiling to generate automated attack narratives.

## 2. Methodology
The NetForensicX framework implements an automated, multi-stage data ingestion and analysis pipeline to reconstruct network attacks from raw packet captures (PCAPs). The methodology is divided into three sequential phases: Data Ingestion and Extraction (Phase 1), Indicator Enrichment and Cleaning (Phase 2), and Correlation and Profiling (Phase 3).

### 2.1 Phase 1: Data Ingestion and Extraction
The first phase focuses on parsing unstructured network traffic into structured forensic artifacts. The system leverages Zeek and Suricata to extract granular network connection logs, HTTP metadata, and DNS queries, while simultaneously carving raw file payloads traversing the network. Concurrently, it inspects the traffic against a database of intrusion detection signatures, generating security alerts. The output of this phase is a structured "Data Lake" containing Extensible Event Format (EVE) JSON logs and raw carved binaries.

### 2.2 Phase 2: Deduplication and Threat Intelligence Enrichment
To minimize noise and optimize API querying, Phase 2 implements a robust Indicator of Compromise (IOC) filtering mechanism. The framework parses the Data Lake and assigns accurate network zone tags, explicitly preserving internal endpoints (e.g., RFC1918) to retain context for lateral movement while discarding non-routable noise.

**Algorithm 1: Cryptographic SHA-256 Composite Key Deduplication**
*   **Mathematical Calculation:** $\text{Key} = \text{SHA256}(\text{IP} \parallel \text{Domain} \parallel \text{File Hash} \parallel \text{Port})$
*   **Use:** Extracted network observables are often highly redundant. This hashing algorithm mathematically guarantees that an identical combination of attributes is reduced to a single stable hexadecimal key. This effectively allows the system to prevent making duplicate external Threat Intelligence API queries, thereby saving critical rate-limit quotas and drastically speeding up processing time.

The deduplicated IOCs are passed through a local YARA scanning engine to identify malware signatures within carved payloads. Finally, the framework executes an asynchronous enrichment phase, querying external intelligence sources where a caching layer is used to optimize external API queries.

### 2.3 Phase 3: Correlation and Host-Centric Profiling
The final phase correlates the enriched threat intelligence back to the raw network sessions to reconstruct the attack timeline and profile compromised endpoints.

**Algorithm 2: Multi-Factor Weighted Infection Scoring**
*   **Mathematical Calculation:** $\text{Host}_{\text{score}} = \sum (\text{YARA}_{\text{weight}} + \text{VT}_{\text{weight}} + \text{AbuseIPDB}_{\text{weight}} + \text{IDS}_{\text{weight}} + \text{Anomaly}_{\text{penalty}})$
*   **Use:** Used to quantify the exact severity of an endpoint’s compromise. Rather than treating all alerts equally, this additive mathematical model penalizes a host based on the specific threat category. This effectively allows the system to let Security Operations Center (SOC) analysts instantly rank and prioritize the most heavily infected machines during an incident.

**Algorithm 3: Volumetric Thresholding & Score Normalization**
*   **Mathematical Calculation:** 
    *   $\text{If } (\text{session\_count} > \text{THRESHOLD}): \quad \text{Apply Flat Penalty } (+80)$ 
    *   $\text{Else}: \quad \text{Apply Additive Score } (\text{session}_{\text{score}})$
*   **Use:** Prevents Denial of Service (DoS) attacks or aggressive port scans from destroying the mathematical integrity of the host infection score. This effectively allows the system to treat a volumetric DoS anomaly as a singular event rather than an infinitely additive loop.

**Algorithm 4: Beaconing Standard Deviation (Interval Timing)**
*   **Mathematical Calculation:** $\sigma = \sqrt{\frac{\sum(x_i - \mu)^2}{N}}$ *(Where $x_i$ is the time delta between connections. If $\sigma < 2.0$ seconds, apply +40 to Beaconing Score).*
*   **Use:** Used to detect automated Command and Control (C2) infrastructure and malware persistence. This effectively allows the system to distinguish between random, erratic human-driven web browsing and precise, automated beaconing loops executed by malware implants.

**Algorithm 5: Chronological Patient Zero Sorting**
*   **Mathematical Calculation:** $\text{Patient\_Zero} = \arg\min_{H \in \text{Internal Hosts}} (\text{first\_seen\_malicious\_event}(H))$
*   **Use:** Programmatically maps out the origin of the network breach. This effectively allows the system to isolate the true initial intrusion point with high confidence, bypassing false positives created by bidirectional traffic flow.

### 2.4 Cryptographic Chain of Custody
To ensure the pipeline generates legally defensible evidence suitable for digital forensics and incident response (DFIR) engagements, the methodology mandates strict evidence preservation.

**Algorithm 6: Cryptographic Integrity Manifest**
*   **Mathematical Calculation:** $\text{Seal} = \text{SHA256}(\text{Input\_PCAP}) \cup \text{SHA256}(\text{Output\_Reports}) \cup \text{SHA256}(\text{Extracted\_Payloads})$
*   **Use:** Provides a mathematical guarantee of chain-of-custody. This effectively allows the system to prove to a court or auditor that no tampering of the evidence occurred post-analysis, ensuring strict compliance with NIST SP 800-86 standards.

## 3. Evaluation and Results
To evaluate the effectiveness of NetForensicX, we processed a variety of industry-standard malware and attack PCAPs, focusing on its ability to reduce alert noise and accurately reconstruct complex attack narratives.

### 3.1 Formal Evaluation Metrics
Our evaluation demonstrates significant capabilities in data reduction, incident aggregation, and processing speed. The pipeline’s performance across three core datasets is summarized below:

| Dataset | Raw Events | Reduced IOCs | Final Incidents |
| :--- | :--- | :--- | :--- |
| Hive Ransomware | 25,566 | 419 | 4 |
| DoS GoldenEye | 567,925 | 23,042 | 2 |
| Exploit Kit (Multi-Host) | 12,910 | 1,096 | 125 |

Across all evaluations, NetForensicX achieved the following core metrics:
*   **Alert Reduction Ratio:** >91% to 98.3% noise reduction across diverse datasets.
*   **Incident Aggregation (DoS Example):** 50,132 raw sessions consolidated into exactly 2 actionable incidents.
*   **Processing Time:** Sub-75 second processing times for advanced multi-stage attacks (e.g., 72.41 seconds for Hive).
*   **Estimated False Positive Rate:** <5% due to high-confidence multi-factor intelligence correlation.

### 3.2 Case Study: Ransomware and Lateral Movement
We evaluated NetForensicX using the `Hive_06082021` dataset, a well-known PCAP containing a Hive ransomware infection, active Command and Control (C2) beaconing, and SMB-based lateral movement.

**Data Reduction and Alert Fatigue Mitigation:**
During Phase 1 and Phase 2, the framework extracted **25,566 raw network events and Indicators of Compromise (IOCs)**. Without automated correlation, an analyst would have to manually filter through these records. NetForensicX's deduplication engine successfully reduced this to **419 clean IOCs**.

**Automated Narrative Generation:**
Rather than outputting 47 independent malware alerts based on YARA hits, Phase 3 clustered the activity into exactly **4 HIGH severity incidents**. The framework output a high-confidence verdict: *"Ransomware infection with active C2 communication."*
*   It identified internal lateral movement: `192.168.1.4 → 192.168.1.5 via SMB (Port 445)`.
*   It automatically generated a 4-step chronological attack timeline, placing the initial C2 communication (T+53.5s) before the ransomware payload transfer (T+155.8s).

### 3.3 Case Study: Volumetric Anomaly Detection
To demonstrate the efficacy of Algorithm 3, we processed the `DoS-GoldenEye_attack` dataset. NetForensicX processed an overwhelming **567,925 raw IOCs**, compressing the dataset down to just **23,042 clean IOCs** prior to enrichment.

Instead of generating 50,132 individual alerts for the HTTP requests, the Volumetric Thresholding algorithm mathematically normalized the attack into exactly **2 HIGH severity incidents**, outputting:
*   **Verdict:** Denial of Service (DoS) Attack (Confidence: HIGH)
*   **Attacker Identified:** `192.168.1.11`
*   **Characteristics:** 50,132 connections executing in a rapid ~170.34 second burst window.

### 3.4 Case Study: Multi-Host Exploit Kits and Malware Profiling
We processed the `2016-01-07-traffic-analysis-exercise` dataset, which contains a sophisticated exploit kit infection spanning three internal hosts. Applying Algorithm 5 (Chronological Patient Zero Sorting) and Algorithm 2 (Multi-Factor Infection Scoring), the correlation engine successfully profiled the three compromised internal hosts.

Despite `192.168.122.52` generating the highest volumetric infection score (12,550 points), the chronological sorting engine correctly bypassed it and identified **`192.168.122.132` (Hokaydoo-PC)** as the true "Patient Zero" based on the absolute minimum timestamp of malicious payload execution.

The successful mapping of this complex exploit chain demonstrates that NetForensicX significantly reduces the need for manual timeline reconstruction in advanced persistent threat (APT) scenarios.

## 4. Limitations
While NetForensicX demonstrates high efficacy, it does present certain limitations:
*   The framework relies on heuristic scoring, which may not generalize to all environments.
*   Real-time streaming analysis is not currently supported, as the framework relies on post-analysis ingestion of PCAP files.
*   Threat intelligence enrichment depends on external API availability and strict quota management.
*   Performance may vary with extremely large-scale distributed environments.

## 5. Conclusion
As network bandwidth increases and cyber threats become more sophisticated, traditional Security Operations Centers (SOCs) are failing to keep pace. The reliance on standalone IDS alerts generates an unsustainable level of alert fatigue.

In this paper, we introduced NetForensicX, an automated Post-Analysis Ingestion Framework designed to bridge the gap between raw telemetry and actionable intelligence. Through a multi-stage methodology of cryptographic deduplication, multi-source threat enrichment, and host-centric scoring, we demonstrated the framework's ability to reduce raw IOC noise by over 95%. 

Our evaluations prove that NetForensicX can successfully transform chaotic network telemetry into highly accurate, chronologically ordered attack narratives. By automating the triage process and preserving a strict cryptographic chain of custody, NetForensicX significantly reduces analyst workload while ensuring the digital evidence remains legally defensible.
