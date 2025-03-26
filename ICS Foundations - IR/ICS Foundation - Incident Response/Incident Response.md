# Incident Response - Preparation
# Incident Response Team

Incident response (IR) teams implement IR planning in ICS environments and apply IT incident response methodologies to OT systems across multiple sectors. The preparation methodologies **emphasize safety, system resilience, and high availability**. The responsible team is composed of *members with a cross-section of expertise* to develop an effective IR plan.

## ICS Incident Response Team

ICS-specific IR teams are similar to standard IT IR teams but include ICS roles. The U.S. National Institute of Standards and Technology (NIST) Special Publications **(SP) 800-82r3** and the ICS Cyber Emergency Response Team (CERT) of the U.S. Department of Homeland Security contain lists of IR team roles that are unique to ICS systems. These are described below:

- **The Control System Engineer** (also called the *Process Engineer*) is an ICS Subject Matter Expert (SME). The Control System Engineer’s main focus encompasses how ICS intersects with the production methods, major components, and end-product specifications in a given environment.

- **The Plant Manager** (including *ICS and Control Center Managers*) holds or delegates authority to stop production, participates in incident risk assessments, ensures adequate Computer Security Incident Response Team (CSIRT) funding, and interfaces with higher management and external entities in ICS matters.

- **Vendor Support Engineers** provide technical assistance to vendor technicians, as needed, to repair or replace equipment and systems. Vendor Support Engineers must have a thorough understanding of vendor-supplied system components.

- **The Safety Manager** ensures the IR plan addresses the safety of all staff members and other individuals who are susceptible to impact. The Safety Manager is familiar with stringent industry safety protocols and procedures.

- **A Representative from Organized Labor** provides knowledge of contractual employee and management obligations. The representative also understands how these obligations impact IR planning and execution.
# Incident Response - Anomaly Detection

Anomaly detection is a process of *discovering events that are outside of normal ICS operations*. Event examples include devices that communicate with systems that are outside the component’s normal group of systems or via a port that the component did not previously use. Such devices include programmable logic controllers (PLC), human machine interfaces (HMI), and historians. IR teams use trends in historical data to create a baseline to compare against new data.﻿

While challenges do exist, it is generally *easier* to detect anomalies in an ICS network than standard IT networks. There is **less** variation in daily ICS traffic compared with most IT networks. The variations in ICS normal day-to-day operations are limited to planned maintenance and configuration changes.

Per the NIST NISTIR 8219 report, anomaly detection in ICS networks falls into the three categories described below.
## 1-Network-Based
- Aggregate network traffic into a single collection point.
- Examine and compare traffic to a pre-existing baseline.
## 2-Agent-Based

- Monitor endpoints, preferably via non-intrusive means.
- Collect information such as:
    - Removable media use
    - Authentication logs
    - Device configurations
    - Process details
    - Device resource information such as disk, memory, and CPU utilization
## 3-Historian-Based

- Collect sensor/component data for ICS devices.
- Maintain constant feed of real-time device information.
- Use data statistics to identify deviations from the operating norm.
# Network Intrusion Detection System (NIDS)

A NIDS collects, i*nspects, and evaluates traffic* against a known set of rules to detect potentially malicious traffic.

System Engineers place NIDS in *strategic locations throughout a network*, most commonly at **ingress and egress points**. NIDS are **passive** devices that perform limited functions such as sending alerts when detecting evidence of known threats or anomalous behavior. Snort and Suricata are examples of common open-source NIDS.
# Network Intrusion Prevention System (NIPS)

A NIPS adds the ability to *block or shutdown* suspected malicious traffic when identified.
﻿
A NIPS takes the concept of intrusion detection further by adding the ability to block or shutdown suspected malicious traffic, if identified. For example, a NIPS detects evidence of an intrusion impacting a power plant coolant pump PLC sensor. If the NIPS shuts down the pump, this could negatively impact other plant systems. Since NIPS are *not passive*, they are only *infrequently* used within OT networks due to their potential to shut down traffic or processes. In many OT environments, that could lead to catastrophic downtime and possible loss of life.
# Incident Response - Network Security Monitoring

Network security monitoring (NSM) operates under the premise that even the best prevention plan will eventually fail. Effective NSM *constantly collects, stores, and organizes data* on multiple network systems to alert network analysts to evidence of anomalous or potential malicious activity. It also requires analysts to be able to interpret, investigate, and respond effectively to those activities in real-time.
## Security Onion

Security Onion is an open-source NSM tool used to collect, detect, analyze, and present network and host-based data. Recent versions also include an instance of *Elastic Stack (formerly ELK Stack)*, which is a security information and event management (SIEM) system that provides a **single point to ingest, normalize, and display query-able data**.

Security Onion collects and analyzes:
- Alert data
- Asset data
- Full content data
- Host data
- Session data
- Transaction data

Security Onion and similar NSM tools present their own challenges, particularly for new analysts. Such large datasets can be difficult to interpret or mine effectively for subtle indications of potential malicious activity. It is helpful to develop specific plans and policies analysts follow when collecting, analyzing, and interpreting NSM data.
# Incident Response - Containment and Eradication

# Containment

Immediately following detection and investigation of a cyber security incident, contain and isolate the threat in order to:
- Stop the spread
- Contain the damage
- Limit the impact
- Prevent further access
![[2a88d49e-2e20-4b88-bce1-d40b74a10650.png]]
## Containment Considerations

Containment plans should include instructions for how to do the following:
- Disconnect affected hosts from the network.
- Block malware sources.
- Shut down affected hosts.
- Redirect affected hosts to/through a sandbox environment.
- Disable services the malware utilizes.
- Block and log unauthorized accesses.
- Change system administrator credentials (even if not known to be compromised).
- Relocate key services (e.g. web home pages, e-mail servers).
# Eradication

The primary objective of eradication is to remove malware from infected systems. Eradication may occur concurrently with containment or immediately after, and should also eliminate — or at least mitigate — any vulnerabilities known to have enabled the initial compromise.
## Common Tools for Eradication

- Antivirus software
- Vulnerability management technologies
- Network access control software

Eradication may involve network-administered, remote antivirus tools, or slower, manual methods. It may even require analysts to physically log in to each local terminal, scan for malware, and manually correct where found.

If the malware is identified and well-understood, the analyst may be able to surgically remove it from infected systems with minimal disruption or additional time required. In some cases, an analyst may have the time and resources to conduct an in-depth analysis of the malware, discover how to remove it, and find ways to defend against future attacks.

In many cases, however, **the safest, most direct method is to completely wipe all impacted systems** and then rebuild, reconfigure, and restore data. This may also be the best option where an attacker has gained administrator or root-level access, a system-level rootkit was installed, or basic functionality has been disabled (e.g., critical files wiped, drivers corrupted, etc.).
## Key Eradication Steps

- Identify all compromised hosts for eradication and remediation.
- Analyze the malware, if possible.
- Develop responses for subsequent identical or similar attacks.
- Look for attacker response to eradication.
