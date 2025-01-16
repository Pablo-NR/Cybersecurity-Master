# 4. SIEM Technologies

## Introduction

**SIEM (Security Information and Event Management)**: Platform that centralizes the management of security events and logs from various systems. It enables real-time detection, analysis, and response to incidents, while also storing logs and generating compliance reports.

A well-configured SIEM provides:

- **Event centralization and global visibility:** Collects and organizes logs from multiple sources into a single platform, simplifying analysis and management.
- **Reports and compliance:** Generates reports to meet legal and security requirements.
- **Advanced detection:** Uses correlation rules, external intelligence, and machine learning to identify threats and issue real-time alerts.
- **Forensic analysis and response:** Supports incident investigation, forensic analysis, and threat hunting, enhancing threat response capabilities.

**Layered Model:** A SIEM is structured into four layers, each with specific functions to efficiently manage and process events:

- **Collection Layer:** Centralizes events from multiple sources (firewalls, antivirus, servers) using active, passive, or agent-based methods.
- **Storage Layer:** Stores large volumes of events for analysis and future queries, aiding forensic investigations.
- **Correlation Layer:** Links events to identify suspicious patterns and detect threats.
- **Presentation Layer:** Provides a visual interface for queries, monitoring, and report generation, supporting security analysts.

**SOC (Security Operations Center):** Center that monitors, detects, and responds to security incidents in real time. Analysts use tools like SIEM to manage alerts, investigate anomalies, and improve threat detection. They also conduct vulnerability assessments and manage fraud.

- **N1:** Filter and classify alerts, follow procedures, and generate basic reports.
- **N2:** Investigate alerts in depth, create rules, and analyze suspicious activities.
- **N3:** Design strategies and handle critical incidents with an advanced approach.

**Key Terms:**

- **Data Source:** A system, application, or device that generates logs that can be integrated into the SIEM (firewalls, proxies, servers, etc.).
- **Integration:** The process of receiving and processing logs from data sources, applying correlation rules, and storing them in the SIEM.
- **Log File:** A file that stores event records. Logs are processed by a parser before being stored in the SIEM.
- **Event:** An individual record within a log that describes a specific action.
- **Parser: T**ool that breaks down raw logs using regular expressions, identifying key fields for SIEM processing.
    1. **Raw Log:** `2024-11-27 10:00:01 INFO User login successful IP:192.168.1.10`
    2. **Date:** `2024-11-27 10:00:01`, **Event Type:** `INFO`, **Description:** `User login successful`, **IP:** `192.168.1.10`
- **Syslog:** A protocol for transmitting logs between network devices using UDP or TCP (port 514).
- **Correlation Rule:** A condition that triggers actions such as alerts or updates when met.
- **Report:** Graphs or tables generated from events in the SIEM, either automatically or through manual filters for specific analyses.

---

## **Collection Layer**

**Collection Layer:** The first step in the lifecycle of a log within a SIEM. Its role is to collect and process logs from various sources (devices, systems, and applications) for analysis, optimizing resource usage. Key steps:

1. **Identification of relevant sources and logs:** Selecting data sources (devices, systems, applications) and critical records for monitoring and anomaly detection.
2. **Integration:** Using methods such as Syslog, files, databases, or APIs to collect logs.
3. **Volume estimation and planning:** Calculating the volume of generated logs and their relevance in correlation rules and threat hunting, considering SIEM limitations (EPS or GB/day).
4. **Log processing:** Adapting logs to ensure their utility and facilitate analysis.

**Log Collection Modes**:

- **Active Collection:** The SIEM directly requests logs from sources using database queries, LDAP, WMI/RPC, and similar methods.
- **Passive Collection:** Sources automatically send logs to the SIEM using methods like Syslog, Windows subscriptions, or agents.
    - **Agents:** Software installed on devices that centralizes and sends logs from the OS, applications, and services to the SIEM. They simplify log collection but consume resources.
    - **Collector:** Intermediate servers that gather logs from multiple sources, process them, and send them to the SIEM to prevent overloading. They are placed near the sources to minimize network issues and firewall blocks.

**Agents**:

- **ArcSight (Connector):** Acts as an intermediary between data sources and the SIEM, installed on devices to collect and process logs based on preconfigured rules. Compatible with Windows and Linux.
    - **Configurable resources:** Resource consumption adjusts to event load and infrastructure needs, making it adaptable to networks of varying sizes.
- **QRadar (WinCollect):** Collects logs locally on Windows devices or from other devices over the network, enabling integration into distributed architectures.

![image.png](https://github.com/Pablo-NR/Cybersecurity-Master/blob/main/Images/image2.png))

![image.png](https://github.com/Pablo-NR/Cybersecurity-Master/blob/main/Images/image3.png)

**Log Collection Process:**

1. **Log Parsing:** Log elements are separated into specific fields using regular expressions (*regex*), allowing the SIEM to process them correctly. This is required for technologies unknown to the SIEM, as common technologies already have predefined parsers.
2. **Normalization:** Extracted fields during parsing are mapped to the SIEM's standard fields, adapting names and formats to the specific schema of each system (each SIEM has a distinct schema).
3. **Categorization:** Logs or events are assigned to specific categories, simplifying analysis. SIEMs include predefined categories but also allow customization.
4. **Aggregation:** Similar events are grouped within a defined time frame, reducing the number of events sent to the SIEM, improving performance, and lowering costs. While configurable, it may result in the loss of details like unique event identifiers.
5. **Filtering:** Irrelevant events are discarded based on defined criteria. Ideally, filtering is done at the source to eliminate irrelevant events as early as possible, optimizing performance and licensing costs. If not feasible, filtering can be done in the SIEM.

---

## Storage Layer

**Storage Layer**: Stores the logs collected by the SIEM for analysis, auditing, and regulatory compliance, balancing performance and retention capacity.

**Storage Features**:

- **Capacity:** Must be sufficient to store large volumes of logs for years, accounting for retention policies and future growth.
- **Performance:** Requires high-speed storage to handle multiple simultaneous queries, supported by powerful **CPU** and **RAM** for efficient real-time analysis.
- **Log Centralization:** Logs from all sources must be stored in a single repository, facilitating audits and ensuring immutability.
- **Aggregation and Filtering:** Should allow grouping of similar events to optimize space usage without losing critical information and enable filtering of irrelevant data to reduce load.
- **Integrity and Protection:** The system must protect logs against tampering, using techniques like hashing and change auditing to ensure data integrity.
- **Rotation:** Manages space by deleting or archiving old logs according to defined policies, preventing saturation.
- **Retention:**
    - **Online:** Logs accessible immediately, typically for 6 to 12 months.
    - **Offline:** Logs stored long-term, retrievable through specific processes.
- **Regulatory Compliance:** Must comply with standards like GDPR, PCI DSS, or ISO 27001, ensuring availability, protection, and accessibility of logs in line with privacy and security policies.
- **Storage Types:** The choice depends on performance, scalability, and data sensitivity needs:
    - **DAS (Direct Attached Storage):** Storage directly connected to the SIEM server (internal disks or external arrays). It offers low latency and ease of configuration but has limited scalability and depends on server hardware. **RAID** is used for redundancy and fault tolerance.
    - **NAS (Network Attached Storage):** Storage accessible through the network, acting as a centralized file server. It is scalable and allows shared access by multiple devices, using protocols like CIFS, NFS, or TFTP.
    - **SAN (Storage Area Network):** A high-speed network (fiber optic) dedicated to storage. It provides large capacity, high performance, and scalability without affecting the main network traffic, ideal for environments requiring fast and massive access to critical data.

![image.png](https://github.com/Pablo-NR/Cybersecurity-Master/blob/main/Images/image4.png)

- **Storage Architectures:**
    - **Disaster Recovery (DR):** Data duplication to a second storage point to ensure service recovery after a disaster. Requires a **recovery plan** to minimize downtime, protecting against natural disasters, power failures, cyberattacks, hardware failures, and terrorism.
    - **High Availability (HA):** System replication to a copy, ensuring continuous availability of data and services. In case of failure, it allows automatic failover to the copy, minimizing downtime and ensuring service continuity.
        - **Active-Active HA:** Both environments operate simultaneously with real-time replication, enabling load balancing and greater fault tolerance while keeping 100% of the service operational.
        - **Active-Passive HA (failover):** Only the primary environment handles the service. In case of failure, the secondary environment takes over, but there may be a small delay in activation, and the secondary may not be fully up-to-date.

**Storage Solutions:**

- **ArcSight Logger (MicroFocus):**
    - Requires RedHat Linux or CentOS, 8 cores, 12 GB of RAM, and 1 TB of disk.
    - Provides real-time monitoring, stores logs in both RAW and normalized formats, and allows fast searches using indexed fields.
    - Supports receiver configurations for log classification and retention policy management.
- **McAfee ELM:**
    - Requires 8 cores, 4 GB of RAM, and 250 GB of disk.
    - Stores logs in RAW format with hashes for integrity, but searches are slower.
- **QRadar (IBM):**
    - Allows defining detailed retention policies and applying filters to data sources.
    - Supports log compression and backup for optimized long-term storage.
- **Indexer (Splunk):**
    - Indexers distribute and store events in indexes, enabling fast searches.
    - Allows configuring different retention periods.
    - Requires high-performance storage (minimum 1800 IOPS).
- **Non-Native Solutions:** **Hadoop, Cloudera**, and **MongoDB** are Big Data platforms that efficiently process large volumes of data.

**Compliance Regulations:** The SIEM must ensure compliance with regulations that protect sensitive and personal information. Key regulations include:

1. **GDPR (General Data Protection Regulation):** Requirements for the protection of personal data (in the EU), where data should only be stored for the time necessary to fulfill the purpose for which it was collected, without specifying a minimum retention period.
2. **PCI DSS:** Applies to companies processing or storing payment card information. Data must be stored online for a maximum of three months, with the option to store it offline for up to one year.
3. **SOX (Sarbanes-Oxley Act):** Regulates accounting and auditing for publicly traded companies in the U.S., preventing financial fraud. It sets specific retention periods for accounting and electronic records.
4. **HIPAA:** Protects patient privacy in the U.S. healthcare sector. Health records must be stored for a minimum of six years, with variations depending on local state regulations.

---

## Correlation layer

**Event Correlation**: Establishing relationships between two or more events generated by different devices within a specified time period to detect abnormal behaviors or policy violations by identifying the temporal sequence of events. If an attack is confirmed, the system generates an alert.

- **Benefits**: Enhances incident visibility by providing a more comprehensive view, facilitating real-time threat detection, and reducing response times.

**Correlation Engine**: A core software component in SIEM systems used to identify and analyze relationships between events from various sources. It employs techniques such as predictive analysis, fuzzy logic, and IOC intelligence to detect anomalous patterns and threats. The choice of engine depends on factors such as:

- Equipment and license costs
- IOC ingestion capacity
- User behavior analysis
- Endpoint integration
- Reporting requirements to comply with regulations

![2024-gartner-siem-mq-AI-img.png](https://github.com/Pablo-NR/Cybersecurity-Master/blob/main/Images/image11.png)

**Security Incident**: An event that compromises the **CIA** (Confidentiality, Integrity, or Availability) of information. Identifying a security incident requires preliminary system analysis to assess the event's impact and severity.

**Correlation Layer**: Uses correlation rules on the collected events to generate real-time alerts based on suspicious patterns or violations of security policies.

- **Functions**:
    - Receives the events processed and normalized by the collection layer.
    - Temporarily stores events during analysis (from 15 to 45 days).
    - Establishes relationships between events to identify anomalous patterns.
    - Generates alerts for detected incidents.
    - Allows analysts to search for specific events.
    - Generates reports to review alerts and incidents.

**Correlation Techniques**:

1. **Event-based Correlation**: Establishes a sequence of events associated with a specific malicious behavior. If this sequence is detected, an alert is triggered. 
2. **Scenario-based Correlation**: Establishes a combination of events that, if they occur in any order within a specific time window, generate an alert, as the temporal relationship between them indicates a potential attack or anomaly.
3. **Statistical-based Correlation**: Compares generated alerts with a predefined "normal" threshold. If the frequency or intensity of events exceeds this threshold, an alert is triggered, indicating a high probability of an attack or anomaly.
4. **Temporal Risk Correlation**: Analyzes the temporal sequence of events, where a previous event increases the risk of an attack or security breach occurring afterward.

**IOC (Indicators of Compromise)**: Fragments of evidence, such as IPs, hashes, cookies, Windows logs, emails, etc., that help quickly identify anomalous behaviors or compromises in a system, reducing response times and the exposure window of an incident.

- **IOC Implementation Models**: Schemes that structure and standardize the sharing and analysis of IOCs, allowing different organizations and systems to efficiently and coherently exchange IOCs.
    - **OASIS Cyber Threat Intelligence (CTI)**: Establishes common protocols and formats for sharing information about threats and vulnerabilities.
    - **IODEF (Incident Object Description Exchange Format)**: An XML schema used to record and share technical information about security incidents. Commonly used by incident response centers (CSIRTs).
    - **OpenIOC Framework**: An extensible XML schema that provides a way to describe technical characteristics that identify a threat, attacker methodologies, or any evidence of compromise.
    

**Correlation rules**: Set of logics applied to events, logs, or flows to identify anomalous patterns and detect security incidents.

- **Simple rules**: Triggered by each event or log generated individually.
    - Detect local or isolated incidents, such as repeated failed login attempts.
    - Easy to configure but have limited capacity to detect complex scenarios requiring more data.
- **Enrichment rules**: Improve the quality of events before storing them by adding additional information or useful metadata, such as vulnerability details or network context.
    - Do not generate correlated events or allow aggregation but help better contextualize events before storage.
- **Complex/advanced rules**: Relate and group events from different sources within a specific time window.
    - Allow setting thresholds, logical conditions, and generating automatic alerts to detect complex patterns (distributed or persistent attacks).
    - Require detailed configuration and a good understanding of event flows.
- **Mixed rules**: Combine real-time events with previously correlated events.
    - Help identify patterns that develop over time, such as persistent attacks or evolving threats that would not be detected by isolated events.

**Phases for rule implementation:**

1. **Scenario Identification**: While some rules may be technology-specific, it is always preferable to abstract the logic to make it adaptable to changes in vendors or technologies.
    - Define the activity to monitor (login attempts).
    - Select the technology responsible for generating the events (in Windows servers).
    - Determine which events generated are relevant (only the failures).
    - Ensure that the audit policy is properly configured to log the necessary events, guaranteeing that relevant logs are enabled.
2. **Threshold and Relationship Definition**:
    - **Temporal Sequence of Events**: Define the order or time window in which events must occur.
    - **Arithmetic and Logical Gates**: Use logical operations (condition X AND condition Y) to determine when a set of events should be considered malicious.
    - **Threshold**: Set how many events must occur within a given time range to be considered an anomaly (10 login attempts in 5 minutes).
        - **On First Event:** When the first event meets the conditions.
        - **On Subsequent Events:** Starting from the second event meeting the conditions.
        - **On Every Event:** For each event meeting the conditions.
        - **On First Threshold:** When the first threshold defined by aggregation is reached.
        - **On Subsequent Thresholds:** Starting from the second threshold.
        - **On Time Unit:** At specific time intervals.
        - **On Time Window Expiration:** When the defined time window expires.
    - **Relation**: Determine which fields must match between events to be considered part of the same pattern (login attempts from the same user or IP).
    - **Deviations and Flows**: Use deviations from the mean or event flows to identify anomalies (100 login attempts in 10 minutes, with the average being 20).
3. **Correlated Event**:
    - When an event is detected, it is enriched with additional information that improves its context (such as vulnerabilities on servers, user roles, or critical networks).
    - **Prioritization**: Alerts are prioritized and dynamically updated based on their impact on the environment, source credibility, and severity, determining which ones are the most critical for management first.
        - **Relevance**: Measures the potential impact of the threat on critical assets.
        - **Credibility**: Evaluates the reliability of the event source and the likelihood that the alert is legitimate.
        - **Severity**: Indicates the risk level of the event, calculated based on enriched data, assigned risk, and mitigation capacity.

**Responses generated by the rules:**

- Email or SMS notifications.
- Update of active lists or sessions.
- Increase in criticality, prioritizing the event based on its impact.
- Creation of a new case or assignment of the event to a previous incident.
- Execution of scripts or commands.
- Enrichment of the event by adding fields to the correlated events and classification of assets based on the event.
- Export of the event for analysis in external systems, such as OpenView, in formats like XML…

---

## Capa de presentación

**Presentation Layer**: Provides graphical interfaces to explore and analyze collected events, making data interpretation easier. It helps identify suspicious patterns and behaviors, monitor system health, and visualize the distribution and volume of events over time.  

**Searches**: Enable the retrieval of stored events based on specific criteria, essential for generating dashboards and reports by providing the necessary data for analysis and visualization.

- **Search Criteria**: Define the events to extract, similar to an SQL query:
    - Selection of required fields.
    - Aggregate functions like COUNT, DISTINCT, AVG, SUM, MIN...
    - Grouping of fields.
    - Filters using boolean operations.
    - Limiting the number of results.
    - Defining a time range for the search.

**Dashboards**: Graphical representations of the state and activity of systems and networks from a security perspective, highlighting key aspects such as compromised hosts, exposed ports, and user activity.

- **Information on a Dashboard**:
    - Elements with the highest activity (compromised hosts, exposed ports, at-risk applications...).
    - Metrics on received events.
    - Volume and distribution of events over time.
    - Anomaly detection (spikes, drops, unusual changes).
- **Advantages**:
    - Clear and summarized visualization to support decision-making.
    - Real-time monitoring within a specific event range.
    - Rapid anomaly detection with immediate visual alerts.
- **Disadvantages**:
    - Insufficient as the sole source for investigations due to lack of deep detail.
    - Requires constant monitoring, which can be demanding for analysts.
- **Graphical Components / Items**:
    - **Distribution Charts / Bar Charts / Pie Charts**: Represent trends and proportions of events.

![image.png](https://github.com/Pablo-NR/Cybersecurity-Master/blob/main/Images/image5.png)

![image.png](https://github.com/Pablo-NR/Cybersecurity-Master/blob/main/Images/image6.png)

![image.png](https://github.com/Pablo-NR/Cybersecurity-Master/blob/main/Images/image7.png)

- **Tables**: Offer higher detail levels, showing specifics such as the number of events per technology.
- **Geolocation Maps**: Leverage data enrichment (e.g., IP geolocation) to display key event destinations collected.

![image.png](https://github.com/Pablo-NR/Cybersecurity-Master/blob/main/Images/image8.png)

**Reports**: Detailed documents about system, user, or key security activities. Unlike dashboards, they provide static, structured information, ideal for audiences requiring in-depth data analysis.

- **Generation**: On-demand or scheduled (e.g., monthly or after an alert).
- **Export Formats**: PDF, CSV, and HTML for easier distribution and storage.
- **Storage Options**: Locally within the SIEM or on external systems (FTP servers, email).
- **Advantages**:
    - Meet regulatory and audit requirements.
    - Flexible and customizable to organizational needs.
    - Facilitate information sharing among teams.
- **Disadvantages**:
    - Static information at the time of creation; updates require regenerating the report.
- **Components**:
    - **Items**: Graphical elements such as bar charts, event distribution charts, and pie charts for visual representation of key information.
    - **Layouts**: Organizational spaces for items, allowing the use of custom or predefined templates depending on the SIEM solution.

---

## Service Models and architectures

**Service Models:** SIEM deployment is flexible, adapting to the specific needs and threats of each organization without compromising quality.

- **"As a Service" Model**: The provider manages the hardware, software, and personnel to operate the SIEM.
    - **Layer Distribution**:
        - **Collection Layer**: At the client.
        - **Storage and Correlation Layers**: At the provider.
    - **Advantages**:
        - Nearly unlimited scalability, adjusted by the provider as needed.
        - Low initial cost.
        - Rapid deployment with pre-existing infrastructure.
    - **Limitation**: The client lacks direct access to provider data, though additional storage can be enabled on the client’s infrastructure.
- **On-Premise Model**: The SIEM is installed and operated entirely on the client’s infrastructure.
    - **Advantages**:
        - Greater control and autonomy for the client.
    - **Limitations**:
        - High investment, as the client bears all costs.
        - Slower deployment, dependent on client resources.
        - Scalability limited by the client’s resource acquisition capacity.

**Architecture Types:** Selected based on the client’s needs, resources, and requirements:

- **All-in-One Architecture**: All layers are hosted on a single server.
    - Best for small environments or pre-production setups.
    - Low cost.
    - No fault tolerance.
- **Distributed Architecture**: Layers are distributed across multiple servers, improving performance and scalability.
    - Best for implementations planning short/medium-term growth.
    - Better performance but higher cost.
    - No fault tolerance.
- **HA Storage Architecture**: Fault tolerance in the storage layer, ensuring data integrity even if a node fails.
    - Best for environments requiring high resilience in storage.
    - **Fault Tolerance**: Medium.
    - Higher cost and better performance than previous types.
- **HA Storage and Correlation Architecture**: High availability in both layers, ensuring service continuity even during failures in one or more nodes.
    - Best for critical environments or those with regulatory requirements for high availability.
    - **Fault Tolerance**: High.
    - Highest cost and performance.

---

## SIEM Complements

**Complementary Systems:** Additional technologies integrated with SIEMs to enhance efficiency and coverage, enabling more accurate detection, faster incident response, and improved security management.

**UEBA/UBA (User and Entity Behavior Analytics)**: Leverages Machine Learning to identify normal behavior patterns and detect deviations, unlike static rule-based SIEMs. Enhances threat detection by focusing on the behavior of users and entities, uncovering suspicious activities that SIEMs might miss.

- **Risk Score:** An adaptive risk score is assigned to each user or entity, increasing with anomalous behavior. Risk escalation may occur linearly or exponentially without generating independent alerts like SIEMs.
- **Threat Hunting:** Provides interactive visualization and detailed analysis of user and entity behaviors, enabling efficient threat investigations.
- **Advantages:**
    - Operates independently of specific rules for each event.
    - Proactively analyzes anomalous behaviors.
    - Improves detection of insider threats and compromised users.
- **Types of Threats Detected by UEBA:**
    - Access outside usual hours.
    - Anomalous use of resources or permissions.
    - Unjustified interactions with sensitive data.
    - Activities from compromised accounts.
- **Key UEBA/UBA Vendors:**
    - **Splunk UBA:** Integrated with Splunk SIEM; simplifies threat hunting using predefined anomalies.
    - **HPE ArcSight UBA:** Paired with ArcSight SIEM, noted for collaborative analysis with Securonix.
    - **IBM QRadar UBA:** Exclusive to QRadar SIEM; easy deployment via IBM’s repository.
    - **Securonix:** Operates standalone or integrates with any SIEM; supports signature-based and external feed detection.
    - **Exabeam:** Flexible integration with any SIEM; provides detailed event timelines for better context.

**Machine Learning (ML):** A branch of AI that enables systems to analyze data, identify patterns, and predict events, thereby reducing analysts' workload.

- **Training:** Models learn patterns using data and adjusted algorithms.
- **Accuracy:** Relies on the quality and quantity of data; training errors can lead to false positives.
- **Types of Machine Learning**:
    - **Supervised:** The model is trained with labeled data, where the outcomes are known (e.g., neural networks, regression).
    - **Unsupervised:** The model works with unlabeled data, autonomously identifying patterns or groupings. Suitable for exploratory analysis.
    - **Reinforcement Learning:** The model learns by interacting with its environment, receiving rewards or penalties based on actions. Commonly applied in robotics and autonomous systems.

**Threat Intelligence Feeds**: External data streams offering information on Indicators of Compromise (IOCs), such as IPs, domains, URLs, emails, and hashes associated with previous attacks.

- **Types:** Free, paid, public, and private feeds.
- **Integration:** Feeds are incorporated into SIEM/UBA to generate real-time alerts and are automatically updated.
- **Customization:** Organizations can create their own feeds or collaborate using platforms like:
    - **MISP:** A collaborative platform for sharing and managing IOCs.

---

## SOC Operations

**Security Incident:** An unexpected event or series of events that breach security policies, potentially compromising organizational information or operations. These incidents can be direct actions (explicit) or indirect consequences (implicit).

- **Urgency:** The time required for the incident to significantly impact business operations; shorter times indicate higher urgency.
- **Impact:** The potential damage the incident could inflict on company services; greater impact leads to higher criticality.
- **Priority:** Determined by combining urgency and impact, defining the relative importance of the incident.

**SIEM-Detected Incidents:** SIEM systems identify incidents through use cases. Optimal management involves centralized incident or ticket management systems that consolidate alerts from multiple sources (e.g., SIEM, antivirus, WAF, manual reports) for a more efficient and structured response.

**Use Case:** A set of processes and rules in a SIEM designed to identify, analyze, and manage security events, from log collection to remediation, aiming to detect threats and effectively respond to incidents.

- **Lifecycle:** Use cases must remain efficient and adaptable to organizational changes to avoid obsolescence:
    - **False Positive:** Incorrect detection of a non-existent threat, overwhelming the system with false alerts.
    - **False Negative:** Failure to detect a real threat, often caused by overly strict thresholds.
    - **Partial Match:** A rule that only partially meets conditions, preventing alerts and causing false negatives.
    - **Simplification:** Breaking down complex rules into simpler ones to improve accuracy and avoid partial matches.
    - **Advanced Testing:** Simulations and penetration tests to verify effectiveness, ensuring the detection of real threats and enhancing forensic analysis.

**Control Lists**:

- **Whitelist:** Excludes authorized elements from detection or blocking rules, such as trusted users or IPs.
- **Blacklist:** Identifies and blocks suspicious or malicious elements, like IPs and domains linked to harmful activities.
- **Suppression Lists:** Temporarily disables alerts for elements under remediation, such as locked users awaiting password changes, preventing unnecessary brute-force alerts during resolution.

**SOC (Security Operations Center):** A centralized facility that continuously monitors, manages, and responds to security incidents, operating 24/7 to protect the infrastructure of one or multiple organizations.

- **Team Structure**:
    - **Level 1 (L1):** Filters and classifies alerts, follows predefined procedures, and generates basic reports.
    - **Level 2 (L2):** Conducts in-depth investigations, creates rules, and analyzes suspicious activities.
    - **Level 3 (L3):** Handles critical incidents and designs advanced security strategies.
- **Security Services:** Device administration (firewall, SIEM, WAF, antivirus), alert management and hardening and ethical hacking.
- **Alert Lifecycle:** Phases from incident detection to resolution and continuous improvement:
    1. **Detection:** Identifying anomalous or suspicious activities.
    2. **Analysis:** Confirming whether the alert is a true positive or a false positive.
    3. **Containment:** Implementing actions to limit the incident's impact (e.g., isolating systems, blocking IPs) while remediation is underway.
    4. **Remediation:** Addressing the root cause and restoring a secure state.
    5. **Lessons Learned:** Post-incident evaluation to improve processes and prevent future occurrences.

**Security Orchestration**: Centralizes and automates security tools and processes to optimize efficiency, especially in response to the growing volume of alerts and data.

- **Resources and Processes**: Automates repetitive tasks, allowing for the management of more alerts with the same team, freeing up time for more complex and valuable tasks such as threat hunting.
- **Technology**: Maximizes tool usage through interconnection and optimization.
- **Requirements**:
    - A dedicated team for incident management.
    - Specialized tools for incident detection.
    - Definition of automated workflows (playbooks) to manage alerts.

**Orchestration in SIEM**: While it can support orchestration by centralizing events and executing automatic actions, it is not its primary function.

- **Examples:**
    - **Windows Events**: Detects suspicious actions (e.g., unusual access) and categorizes them as potential threats.
    - **IOC**: Upon receiving IOCs, such as malicious file hashes, the SIEM can trigger automatic actions (e.g., isolating systems, scanning with antivirus, opening tickets).
    - **System Health Monitoring**: Analyzes network and CPU usage to trigger remediation measures or open tickets based on criticality.
- **Limitations of SIEM in Orchestration**:
    - Not designed for complex workflows or native integration with third-party systems (e.g., firewalls).
    - Extending SIEM capabilities with scripts is impractical due to maintenance effort, lack of specialized knowledge, and integration limitations.
- **Effective Solution**: Let the SIEM handle log collection, event analysis, and alert generation, while a dedicated orchestrator automates responses (e.g., blocking IPs) and manages integrations with other tools, such as automatic ticket creation.
- **Commercial Solutions**: Selected based on their ability to integrate with third-party tools, either natively or via non-native integrations (using languages like Python, JavaScript, or APIs). Some offer trial versions with limited functionality for evaluation.
    - Phantom
    - Demisto
    - Komand
    - CloudGuard IaaS
    - D3 Security

---

## SIEM Vendors

**SIEM Vendors:** Offer solutions tailored to different needs, combining common functions with specific features based on the sector and environment. The choice depends on client requirements and business model.

- **Banking Sector**: Prefer SIEMs with a focus on security and regulatory compliance, typically on-premise to protect logs.
- **Cloud Environments**: Seek flexible, scalable solutions that can adapt to the growth and characteristics of the environment.

**Forrester Report**: A market analysis publication evaluating technologies and tools such as DLP, WAF, and antivirus, providing recommendations for technology decisions.

- **Evaluation Criteria (36 controls grouped into 3 categories):**
    - **Services Offered (Y-axis)**: Analyzes capabilities such as architecture, threat detection, event management, **threat intelligence**, automation, and user experience.
    - **Strategy (X-axis)**: Considers partnerships, roadmap, deployment model, and pricing.
    - **Market Presence**: Indicated by the size of the bubbles, based on customers, revenue, and satisfaction.

![Security Analytics Platforms 2022](https://github.com/Pablo-NR/Cybersecurity-Master/blob/main/Images/image10.png)

Security Analytics Platforms 2022

**Gartner Report**: A technology consulting firm providing strategic analysis and advice. Its **Magic Quadrants** are key references for evaluating technologies and vendors.

- **Evaluation Criteria:**
    - **Ability to Execute (Y-axis)**: Assesses user experience, support, sales, after-sales service, and market presence.
    - **Vision (X-axis)**: Examines marketing strategy, sales, innovation, product development, and sector adaptability.

![Security Information and Event Management 2024](https://github.com/Pablo-NR/Cybersecurity-Master/blob/main/Images/image11.png)

Security Information and Event Management 2024

### **Most Recognized SIEM Vendors**:

**IBM** **QRadar**: Main components:

- **Collection Layer:**
    - **Event Collector:** Collects events from various sources (physical or virtual).
    - **WinCollect:** Agent for Microsoft events (Windows, DNS, DHCP).
    - **Flow Collector:** Captures and normalizes network flows.
- **Correlation Layer:**
    - **Event Processor:** Processes and correlates events to detect threats.
    - **Flow Processor:** Processes network flows and correlates them with events.
- **Storage Layer:**
    - **Event Processor:** Stores events by default.
    - **Data Nodes:** Extend long-term storage.
- **Presentation Layer:**
    - **QRadar Console:** Centralized web interface for management and administration.
- **Additional Components:**
    - **Vulnerability Manager:** Scans and manages vulnerabilities, integrating results into the asset database.
    - **Risk Manager:** Monitors network configurations (routers, switches) and prioritizes risks.
    - **X-Force:** Provides **threat intelligence** feeds to identify threats.
    - **UBA:** Analyzes user behavior patterns.
    - **Watson:** Uses AI to contextualize alerts, reducing false positives.
- **Architectures:**
    - **Basic (AllIn1):** Combines the Event Collector, Event Processor, and console into a single machine. Ideal for simple installations but with limited capacity.
    - **Advanced:** Supports **high availability (HA)** and **disaster recovery** for critical environments.
- **Licensing:** Based on **messages per second (MPS)**. If the contracted limit is exceeded, additional events are discarded.
- **Strengths:**
    - Easy installation with web access.
    - Preconfigured reports and dashboards.
    - Supports HA and disaster recovery.
    - Marketplace for integrations and automation.
- **Weaknesses:**
    - Does not normalize all fields during collection.
    - Incident management limited to notifications and basic follow-up and remediation actions.

**Splunk**: Not a pure SIEM, but highly customizable and allows advanced analysis tasks. Main components:

- **Collection Layer:**
    - **Universal Forwarder:** Lightweight agent that collects events from systems (Windows, Linux) and various formats (files, WMI, syslog).
    - **Heavy Forwarder:** Collects and sends events to Indexers from independent machines.
- **Correlation and Storage Layer:**
    - **Indexer:** Stores and correlates events in a single component.
- **Presentation Layer:**
    - **Search Head:** Centralized console that manages searches and coordinates information stored in Indexers.
- **Control Elements:**
    - **Master Cluster:** Manages replication between cluster nodes.
    - **License Server:** Manages licenses.
    - **Deployment Server:** Facilitates deployment of components in distributed environments.
- **Architectures:**
    - **Basic (AllIn1):** All components on a single server, ideal for small environments.
    - **Advanced:** Distributed architectures with support for high availability (HA) and high performance (HP).
    - **Flexibility:** Allows use of **commodity hardware**, leveraging recycled servers if they meet the requirements.
- **Licensing:** Based on the daily ingestion of indexed data (not by EPS).
    - **Subscription:** Periodic payment, usually annual.
    - **Perpetual:** One-time initial payment plus annual support (20% of the initial cost).
- **Strengths:**
    - **Search Engine:** Efficient and flexible.
    - **Customization:** Wide variety of community-developed apps and ease of creating custom solutions.
    - **Interface:** Intuitive and user-friendly.
    - **Scalability:** Modular and easily adaptable to growing needs.
    - **Collection Agility:** Processes data quickly as it does not require prior normalization.
- **Weaknesses:**
    - **Not a pure SIEM:** The user must implement security rules and logic.
    - **Correlation:** Less flexible than dedicated SIEM solutions.
    - **Compression:** Less efficient in managing event storage

**MicroFocus ArcSight:** Main components:

- **Collection Layer:**
    - **Connectors:** Agents that receive and read events from various technologies, performing tasks such as filtering, aggregation, categorization, and normalization.
    - **SmartConnectors:** Native connectors for over 300 technologies.
    - **FlexConnector:** Development framework for integrating unsupported technologies.
    - **ArcMC:** Centralized management of connectors.
- **Correlation, Storage, and Presentation Layer:**
    - **Activate Framework:** Allows sharing and distribution of correlation rules centrally.
    - **ESM (Enterprise Security Manager):** Correlates events, stores them, and provides access.
    - **Logger:** Long-term storage accessible via a web interface that facilitates searches and presentations.
- **Architectures:**
    - **Collection Layer:** Can be distributed according to needs.
    - **Correlation/Presentation Layer:** Centralized, with high hardware requirements to support high availability (HA).
- **Licensing:** Based on gigabytes per day (GB/day) processed.
    - Licenses for software, maintenance, and amount of data processed.
    - Allows exceeding the GB/day limit up to five times in 30 days without losing functionality.
- **Strengths:**
    - **Wide native technological coverage**, with support for over 300 technologies.
    - **Logical separation** between event correlation and storage.
    - **Normalization and filtering** performed at the collection layer.
    - **Multi-client platform** native, ideal for environments with multiple clients.
    - **Pattern discovery:** Threat detection using predefined patterns.
- **Weaknesses:**
    - **Complex** to implement and manage.
    - **High licensing cost**.
    - **Limited capacity** for reporting and dashboards.
    - Requires **high resources** to maintain **high availability** and efficient communication.

**McAfee ESM:** Main components:

- **Collection Layer:**
    - **Receivers:** Responsible for collecting events from various sources.
- **Correlation Layer:**
    - **ACE (Advanced Correlation Engine):** Correlates events and performs necessary analysis.
- **Storage Layer:**
    - **ELM (Enterprise Log Management):** Manages event log storage.
- **Presentation Layer:**
    - **ESM:** Central point of the solution, orchestrates and manages the different components.
- **Strengths:**
    - **Modularity:** Facilitates the design and scalability of architectures.
    - **Speed:** Uses a proprietary non-relational database (NitroEDB), improving search and data ingestion performance.
    - **Database and Application Monitoring:** Good integration with database and application-specific events.
    - **Historical Correlation:** Allows correlation of past events.
    - **SCADA Integration:** Good integration with SCADA protocols.
- **Weaknesses:**
    - **Stability:** The platform can be unstable due to the number of modules and high bandwidth consumption between them.
    - **Limited Correlation:** Correlation capability is more limited compared to other SIEM solutions.
    - **Non-native Integration:** Integrating unsupported sources is not straightforward due to the lack of a development framework.
    - **User Interface:** Although web-accessible, the interface is not as intuitive as other solutions, similar to ePO or NSM.

**LogRhythm:** Main components:

- **Collection and Storage Layer:**
    - **Log Manager (LM):**
        - **Data Processors (DP):** Responsible for collecting events from various sources.
        - **Network Monitor:** Centralizes the collection of network flows.
        - **Data Indexer:** Handles the indexing of events to facilitate their search and subsequent analysis.
- **Correlation Layer:**
    - **AI Engine (AIE):** Correlates events, identifying incidents and behavior patterns.
- **Presentation Layer:**
    - **Event Manager (EM):** Centralized console for managing, analyzing, and visualizing events and alerts.
- **Strengths:**
    - **Combination of functionalities:** Integrates SIEM with endpoint monitoring and UEBA (User and Entity Behavior Analytics) capabilities.
    - **Automated response:** Allows actions to be executed on remote systems in response to incidents.
    - **Interactivity:** Provides an interactive and customizable user experience with dynamic workflow integrations and security monitoring.
- **Weaknesses:**
    - **High cost:** Requires a high number of indexers to process large volumes of events (more than 10,000 EPS), which increases deployment costs.
    - **Less widespread:** Although it has advanced technology, its adoption is more limited, likely due to the lack of a major company backing it.
