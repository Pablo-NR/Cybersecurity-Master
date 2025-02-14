# 7. Forensic analysis

## Introduction

**Computer Forensics**: Discipline focused on identifying and collecting evidence from incidents involving devices or systems that process, transmit, or store digital data.

- **Main Objective**: Verify facts, origin, and authorship through specialized techniques that ensure the validity of digital evidence, while identifying software, hardware failures, and human errors using methods such as system reconstruction and analysis of residual data.

**Key Concepts to Differentiate:**

- **Alert:** A notification indicating a threat level to users, systems, or information, requiring actions to prevent it from materializing into an incident or crisis.
    - **Examples:**
        - Attempted remote connection from a malicious IP
        - Receipt of spam
        - Temporary outage of a non-critical service
- **Incident:** An action compromising the confidentiality, integrity, availability (CIA), or authenticity of systems or data through violations of controls or policies, without escalating to a crisis.
    - May arise suddenly or gradually.
    - Once identified, they are predictable and manageable with predefined plans.
    - Resolved quickly.
    - Manageable impacts.
    - Minimal media attention.
    - **Examples**:
        - DoS/DDoS attack
        - Use of accounts that should be disabled
        - Transfer to a malicious bank account
- **Crisis:** An abnormal or unpredictable situation that threatens the strategic objectives, reputation, or viability of an organization, requiring significant resources for resolution due to its high complexity.
    - Originates from uncontained incidents or latent issues.
    - Unpredictable, requiring strategic, flexible, and creative responses.
    - Demands prolonged and sustained efforts.
    - Strategic-level impacts with wide-reaching and hard-to-assess consequences.
    - Attracts public attention and may harm reputation.
    - **Examples**:
        - Ransomware infection
        - Data breach

**Types of Attackers:**

- **Crackers:** Individuals with advanced knowledge in programming, networks, and systems who conduct attacks, often using malware, and operate in teams. They are difficult to detect due to their high level of expertise and ability to eliminate evidence.
- **Mafias:** Criminal organizations that engage in extortion via the internet alongside traditional activities. They hire or include crackers to perform attacks such as phishing and cyber extortion.
- **Cyberterrorists:** Use digital resources to create fear, chaos, or intimidate governments and civilian populations for social or political purposes.
- **Hacktivists:** Individuals who use information technology to promote political causes, such as human rights or freedom of expression. They typically act anonymously and focus on protest or activism.
- **Companies:** Competitors who employ crackers to access confidential information, destabilize rivals, and gain commercial advantages.
- **Governments:** Conduct cyberattacks to acquire strategic information, safeguard national interests, or destabilize other governments through espionage, election manipulation, and malware deployment.

**Cyberattack Development:**

1. **Information Gathering:** A crucial and labor-intensive phase that defines the target, timeline, start and end points, attack methods, and evidence removal strategies.
    - Information is collected from public sources about operating systems, software versions, databases, antivirus programs, and security mechanisms.
    - Employees are investigated through social media, analyzing public data such as educational background, interests, hobbies, and attended events.
2. **Implementation Phase:** A technical phase where the victim is deceived through identity spoofing and fake profiles using social engineering techniques.
    - Trust is gained by presenting authentic-looking documentation from the company or its suppliers.
    - Victims are infected through manipulated websites or emails containing malware or remote control programs, linking them to the attackers' control network.
3. **Control Phase:** A complex phase where attackers maintain control over victims' devices while avoiding detection.
    - The cracker uses a control panel to communicate with malicious programs on infected devices.
    - Once in control, the attacker expands access within the organization, capturing usernames, passwords, and relevant information.
    - This phase may last until the attackers and their methods are detected, enabling incident analysis.

**Types of Incidents:**

- **Abusive Content:** Mass spam distribution, hate crimes (cyberbullying, racism, threats), and dissemination of child pornography or violent material.
- **Harmful Content:** Systems infected with malware, connections to command and control (C&C) servers, and misuse of internal resources for malware distribution.
- **Information Gathering:** Techniques such as network scanning, network traffic analysis (sniffing), and social engineering to deceive and collect data.
- **Intrusion Attempt:** Exploitation of known vulnerabilities or credential breaches through brute force attacks.
- **Intrusion:** Compromise of accounts or applications by exploiting software vulnerabilities, or physical intrusions for theft or unauthorized access.
- **Availability:** Incidents affecting service, such as DoS/DDoS attacks, misconfigurations, physical sabotage, or external disruptions.
- **Information Compromise:** Unauthorized access to data (through credential theft or physical access), unauthorized modification of information (ransomware), and data loss due to technical failures or theft.
- **Fraud:** Misuse of resources for profit, installation of unlicensed software, or copyright violations.
- **Impersonation:** Attacks like phishing or other methods to impersonate entities and deceive victims for information or illicit benefits.
- **APT (Advanced Persistent Threat):** Sophisticated attacks targeting specific organizations.

**Impact:** Determines the urgency of forensic analysis by evaluating the consequences of the attack on the CIA triad of functions, assets, and affected individuals within the organization.

- **Factors for Evaluating Impact:**
    - Alteration of information integrity.
    - Classification of compromised information (clients, suppliers, employees, business).
    - Duration and level of unavailability.
    - Propagation capacity of the attack.
    - Affected assets.
    - Economic impact.
    - Reputational damage.
- **Impact Levels:**
    - **High:** Affects critical systems, causes revenue loss, or directly impacts customer service.
    - **Medium:** Affects the continuity or availability of systems and information, but is not critical and does not disrupt services. Includes time-sensitive internal frauds.
    - **Low:** Incidents in non-critical systems or long-term investigations requiring detailed analysis without immediate containment.

**Incident Management:** A structured process in phases, ranging from detection to incident closure, aimed at ensuring an effective response and continuous improvement.

1. **Preparation:** Establishes preventive measures, protocols, and training activities to ensure the team and organization are prepared to handle incidents effectively.
2. **Detection:** Identifies alerts, events, or indicators to determine if they represent a potential cyberincident and proceed with further detailed analysis.
3. **Analysis:** Evaluates the nature, severity, and scope of the incident, and establishes containment, eradication, and recovery plans based on triage and evidence analysis.
4. **Containment:** Limits the impact and prevents the spread of the incident through short-term measures (isolation) and long-term measures (patches or removal of malicious files).
5. **Eradication:** Removes the root cause of the incident and implements actions to resolve it permanently, adapting measures based on the type and complexity of the incident.
6. **Recovery:** Restores systems and services to their normal state after ensuring the complete removal of the threat.
7. **Post-Incident:** Analyzes and documents lessons learned to improve future processes, evaluating performance and taking actions to strengthen security and prevent future incidents.

---

## Forensic Methodology

**Forensic Methodology**: A set of procedures and standards for acquiring evidence in a reproducible and reliable manner, ensuring its integrity through the chain of custody. While there is no universal methodology, international best practices enable proper preparation for incidents.

- **Key Recognized Standards:**
    - **NIST 800-86:** Guide to integrating forensic techniques into incident response; widely used in the US and Europe.
    - **NIST 800-61:** Similar to NIST 800-86, focused on incident response.
    - **ISO/IEC 27035:2016:** Management of events, incidents, and information security vulnerabilities.
    - **ISO/IEC 27037:2012:** Guidelines for specific activities in handling digital evidence.
    - **UNE 71506:2013:** Requirements for managing the lifecycle of electronic evidence.
- **Current International Legislation (European Parliament and Council):**
    - **Directive 2006/24/EC:** Regulates the retention of data generated or processed in public electronic communication services and networks, establishing obligations for providers regarding such data.
    - **Directive 2013/40/EU:** Defines minimum requirements for criminal offenses and penalties for attacks on information systems.
    - **Regulation (EU) 2016/679, GDPR (General Data Protection Regulation):** Standardizes personal data protection across the EU, providing citizens more control and organizations greater responsibility. It includes severe economic penalties, especially for failing to notify incidents.
- **Current National Legislation:**
    - **Spanish Constitution:** Establishes fundamental rights relevant to cybersecurity, such as data protection, communication secrecy, privacy, and effective judicial protection.
    - **Criminal Code:** Defines crimes related to cybersecurity, including:
        - Violations of intimacy, honor, and privacy.
        - Electronic fraud (scams).
        - Damage to computer systems or files.
        - Misuse of terminals and passwords.
        - Hacking and document forgery.
    - **Specific Laws:**
        - **Civil Procedure Code:** Regulates civil processes with guarantees of effective judicial protection.
        - **Law on Information Society Services and Electronic Commerce (LSSI-CE):** Protects online services and consumer rights.
        - **Law on Data Retention Related to Communications and Public Networks:** Preserves data relevant to tracking illicit activities and improving security.
        - **Organic Law on the Protection of Personal Data and the Guarantee of Digital Rights (LOPDGDD):** Adapts GDPR in Spain, regulating personal data protection.

**Forensic Analyst**: A professional responsible for investigating, collecting, and analyzing digital evidence related to an incident. They use specialized techniques and tools to determine what happened and document their findings in a detailed technical report.

**Forensic Expert**: A specialist tasked with validating the evidence collected by the analyst and presenting it as legal evidence in a judicial process. They interpret technical findings and explain them clearly to the judge or court, ensuring their admissibility and relevance to the case resolution.

**Forensic Laboratory**: A secure space equipped with specialized tools, devices, and procedures for conducting digital forensic analysis, preserving the chain of custody, and ensuring the legal validity of evidence.

- **Functions**:
    - Propose preventive measures and manage corporate risks.
    - Investigate digital frauds and analyze incidents.
    - Manage data relevant for litigation.
    - Write and defend expert reports.
- **Composition**:
    - **Specialists**: Technical-forensic director, specialized technicians, and legal support (including a notary if necessary).
    - **Tools**: Extraction equipment, analysis tools, evidence exploitation devices, and terminals designed to preserve the chain of custody.
    - **Procedures**: Specific policies and regulations that govern operations.
- **Laboratory Security**:
    - **Physical Controls**: CCTV surveillance, restricted access, and authorized personnel.
    - **Environmental Regulation**: Controlled temperature and S3 gas systems.
    - **Segregated Areas**: Separation between test and production environments to comply with legal standards.
    - **Certified Devices**: Cloners, extraction tools, secure storage, and fingerprint management systems.

**Chain of Custody**: A controlled procedure that ensures the traceability and integrity of digital evidence from its collection to its presentation in court, guaranteeing its validity and admissibility.

- **Key Points**:
    - Applies to both hardware (physical devices) and software (extracted data).
    - Ensures that the evidence presented is the same as that collected, without alterations.
    - A break in the chain of custody invalidates the evidence as legal proof.
- **Procedure Phases**:
    1. **Evidence Collection**:
        - Identify and protect evidence at the incident site.
        - Document with photographs and videos, recording the date, time, and context.
        - Label and package evidence to prevent contamination or damage.
    2. **Proper Preservation**:
        - Protect evidence from alterations, damage, or loss.
        - Maintain a detailed inventory with unique identifiers (serial numbers, codes).
    3. **Controlled Handover**: Record each transfer of custody, specifying who, when, where, and for what purpose the evidence was handled.

**Phases of Forensic Analysis**:

1. **Preservation Phase**: The initial stage that ensures the integrity of digital evidence from collection to analysis, protecting original devices.
    - **Key Measures**:
        - **Integrity and Authenticity**: Use of hashes to verify that evidence remains unchanged.
        - **Secure Storage**: Evidence stored in environments with seals and labels that meet security standards.
        - **Safe Handling**: Use of gloves, anti-static equipment, and precautions against physical or electronic damage such as accidental connections or radio frequency signals.
        - **Forensic Copy**: Creation of exact replicas for analysis, ensuring the original remains unaltered.
    - **Notary**: An impartial public official who certifies the legality of the evidence collection process with a public deed, ensuring its initial state and preventing tampering.
        - Does not replace the expert, as they do not perform technical analysis or guarantee the integrity of the evidence.
        - Their involvement may be required in judicial cases to validate the evidence before a court.
    - **Subphases**:
        - **Securing the Scene**: Preserve the incident site without alterations and document appropriately, especially for legal cases.
            - **Key Data to Record**:
                - Requester's information (name, contact).
                - Date, time, and photographs of the scene.
                - Scope of the incident and affected devices.
                - Description and assessment of the incident.
                - Access authorization.
                - Tools and equipment used.
            - **Actions to Preserve Integrity**:
                - Inform the responsible party for the devices to prevent manipulation.
                - Restrict access to the affected area.
                - Disconnect the network and keyboard on shared devices.
                - Avoid turning devices off or on.
                - Document all actions performed to prevent alterations.
            - **Judicial Assessment**: If the case is judicialized, request a notary to certify the evidence.
        - **Evidence Acquisition**: Make copies of evidence while ensuring integrity and avoiding contamination.
            - **Authorization**: Obtain written authorization from the equipment owner. If an external forensics team is involved, formalize it with a contract.
            - **Legal Compliance**: Ensure a notary is involved, if necessary, to certify the validity of the process.
            - **Evidence Collection**: Prioritize capturing volatile evidence, such as RAM, before proceeding with cloning hard drives and other persistent data.
                - **Triage**: Quickly acquire volatile evidence (such as RAM, active processes, and logs) before the full disk cloning to prevent the loss of volatile information that may disappear during the lengthy cloning process.
            - **Documented Procedure**: Record each step of the process in detail to ensure the chain of custody and traceability of evidence.
2. **Analysis Phase**: A technical phase aimed at identifying what happened, who caused it, how it was executed, and the consequences of the incident for resolution.
    - **Key Aspects**:
        - Prepare the laboratory and working environment.
        - Verify the prior chain of custody to ensure the integrity of the evidence.
        - Create a timeline to reconstruct the incident.
        - Identify the attack's author and the attacker's modus operandi.
        - Evaluate the incident's impact.
    - Specialized software and hardware tools are used, prioritizing recognized ones or those with access to the source code.
    - Results must be reproducible by other analysts to ensure reliability.
3. **Presentation Phase**: Document the findings obtained during the analysis, organized in a report detailing what occurred.
    - **Recommendations**:
        - Document all actions performed during the investigation to facilitate report preparation.
        - Include evidence in logical order, detailing the tasks performed to ensure reproducibility.
        - Use clear technical language, adjusting the complexity to the target audience.
    - **Types of Reports**:
        - **Executive Report**: Targeted at non-technical readers, such as management. It summarizes key aspects clearly, avoiding jargon.
        - **Technical Report**: Directed to technical specialists, allowing the reproduction of the process. It thoroughly details the analysis, methodology, tools, and results obtained. In judicial cases, it is presented as an expert report.
    - **Typical Report Content**:
        1. **Object and Scope**: The purpose of the investigation and the context of the incident being analyzed, along with the systems or evidence analyzed.
        2. **Evidence or Samples Received**: Details of the evidence, including associated identification, origin, initial state, and collection method, maintaining the chain of custody.
        3. **Studies Performed**:
            - **Evidence Extraction**: Description of the procedures and tools used, including hash generation to ensure integrity.
            - **Cloning**: Details of the exact replication process of the data.
            - **Analysis of Acquired Evidence**: Explanation of the methods applied and the most relevant findings obtained.
        4. **Conclusions After Analysis**: A summary of results, indicating what happened, how the incident occurred, possible guilty, and the impact generated. Finish with proposals based on findings, such as corrective or preventive measures.
        5. **Appendices**: Additional information supporting the analysis, including logs, screenshots, tables with relevant data, documentation of tools used, hashes generated, photos, or videos of the scene.
        

---

## **Evidence Acquisition Process**

**Evidence Acquisition Process**: A critical phase in forensic analysis that ensures the validity and usefulness of the obtained evidence for subsequent analysis. This process must be carried out with precision, documenting all steps, including mistakes, to guarantee the integrity of the information and its validity in legal proceedings.

- **Procedure**:
    1. **Initial Photography**: Take a photograph of the scene and a screenshot with the date and time, as long as the system is powered on.
    2. **Collection of Volatile Evidence**: Obtain data on network connections, running processes, logged-in users, and RAM.
    3. **Acquisition of Non-Volatile Evidence**: Capture the hard drive and other storage devices (USB drives, CDs, logs, etc.).
- **Recommendations and Best Practices**:
    - **Isolate the scene** to prevent unauthorized access.
    - **Locate the system and communication administrator**, in case technical support is needed.
    - **Label devices and cables** associated with relevant evidence.
    - **Locate wireless devices**, identifying their communication modes. If necessary, activate equipment to block external radio frequency interference.
    - **Do not share malware samples** on platforms like VirusTotal, Ayrun, or Hybrid Analysis, as attackers could modify their attack once they know it has been discovered.
    - **Document each step** of the acquisition process in detail, including errors, to ensure a thorough analysis and the creation of a final report.
    - Follow a **structured methodology**, ensuring that the proper steps are followed in each phase of the forensic analysis.
- **Scenarios Before Acquisition**:
    - **System On**: Do not power off the system. Begin volatile evidence acquisition immediately.
    - **System Off**: Do not power on the system. Proceed with cloning the device.
    - **Virtualized System**: Clone the virtual environment to obtain volatile evidence. Later, power off the system and transfer it to the forensic laboratory.
    - **Cloud System**: Verify the contract between the organization and the cloud provider, as it may limit forensic analysis options due to potential data sharing with third parties.

**System On**: In this situation, the collection of volatile data, which is most likely to be lost, should be prioritized, ensuring its proper preservation and documentation.

- **RAM Memory**: A key source of volatile evidence, crucial for analyzing running processes and recent system activity.
    - **Important**: Minimize interactions with the system to prevent data overwriting.
    - **Tools for Acquisition**: Belkasoft Live RAM Capturer, FTK Imager, or Volatility.
    - **Contents of RAM**:
        - Running and terminating processes.
        - Active network connections and open ports.
        - Data such as text, passwords, emails, and web addresses.
        - Hidden or temporary elements, like cached files or malware data structures.
- **Other Volatile Data to Collect**:
    - **System Event Logs**: Information about recent system activity and errors.
    - **DNS Cache and ARP Tables**: Track queried domains and connected devices.
    - **Active Users and Sessions**: Identify suspicious activity or remote connections.
    - **Open File Systems**: Evidence of files in use or locked.
- **System Boot Process**:
    1. The microprocessor reads instructions from the ROM.
    2. The POST (Power-on Self-Test) is executed to check the proper functioning of the system components.
    3. The BIOS or UEFI is loaded, providing information about storage devices.
- **Additional Considerations**:
    - **Encrypted Disks and Password-Protected Files**: If encryption is suspected, extract decryption keys stored in RAM before powering off the system. Perform decryption only on a copy of the evidence to preserve the integrity of the original.
    - **Preservation of Active Malware State**: Capture suspicious executables and document their behavior with tools like Process Monitor or Wireshark.
    - **System Isolation**: Disable network connections to prevent remote modifications. Use a controlled environment that allows the use of acquisition tools without compromising the integrity of the evidence.

**System Powered Off**: When encountering a powered-off system, the priority is to preserve the state of storage devices through forensic techniques.

- **Cloning**: A technique that creates an exact, bit-by-bit copy of a powered-off storage device. It helps preserve the evidence in its original state, avoiding the loss of volatile evidence. The copy is so accurate that errors or defective sectors present on the original device are also replicated.
    - **Legal Certification**: To use the cloned evidence in legal proceedings, a notary is required to ensure that the cloned evidence is faithful to the original.
    - **Creating Copies**: Generally, two copies of the device are made: one for the client and one for the analyst, with the original remaining under the notary's secure custody.
    - **Importance**: Analysis is conducted on the copies, preserving the integrity of the original evidence, which is critical for maintaining validity in judicial investigations.
- **RAW Format**: Bit-by-bit cloning of a storage device, generating an exact copy that preserves all sectors, ensuring the integrity of the original. This is useful for forensic analysis.
    - **Full Data Inclusion**: The copy includes both visible and hidden data, metadata, and file system structures, such as partition tables, which are essential for understanding the original structure of the device.
    - **No Processing**: No interpretation or filtering of data is performed, which preserves the original structure. File types are not identified or organized (e.g., images, documents, or videos), and the data is copied as-is, without alterations.
    - **Uncompressed**: Data is not modified or compressed, ensuring a faithful reproduction, though it results in a larger file size.
    - **Specialized Access**: Requires forensic tools that can directly read the device's sectors and recognize storage structures without needing an operating system for interpretation.
        - **Examples**: FTK Imager, Autopsy, or X1 Social Discovery.
- **Cloning Types by Cloning Method**:
    - **Software Cloning**: Uses Linux distributions designed for forensic analysis to clone devices (hard drives, USBs) using software tools.
        - **Example**: AIR, a tool in the CAINE distribution, allows selecting the source and destination disks while calculating hashes (MD5, SHA-1) to ensure the integrity of the copy.
        - **Advantages**: Easy to use and configure, does not require additional hardware, and includes a write-blocker.
        - **Disadvantages**: Slow process, not suitable for large-capacity disks.
    - **Hardware Cloning**: Uses specialized devices with high-speed buses and lightweight assembly systems to optimize the cloning process. Integrity hashes are calculated to verify that the copies are identical to the original.
        - **Example**: **Tableau Forensic Imager**, a hardware device that enables fast and precise disk cloning. It calculates integrity hashes (MD5, SHA-1) to ensure the copy is identical to the original.
        - **Advantages**: Easy to use, high cloning speed (up to 30GB/min), suitable for large disks.
        - **Disadvantages**: High cost.
- **Cloning Types by Cloning Destination**:
    - **Disk Cloning**: Transfers the contents of one hard drive to another with the same size and geometry.
        - In **Windows**, the cloned disk is automatically detected as an external device, allowing immediate access.
        - In **Linux**, the disk must be manually mounted using the `mount` command.
        - Generally faster than cloning to an image, as no image file needs to be created.
        - The copy functions exactly like the original disk, so access to the copy is direct.
    - **Image Cloning**: Creates a single file containing a complete copy of the disk, similar to a compressed file (.ZIP), making it easier to store and manage large data volumes.
        - Images can be compressed, allowing multiple backups to be stored in a single file.
        - Can be sealed with a hash to ensure data integrity.
        - Creating an image is generally slower than cloning to a disk due to the image file creation.
        - **Image Access**:
            - **RAW Access**: Accesses the unprocessed data of the image using specialized tools, like **FTK Imager**, which allows reading the image without interpreting its structure.
            - **Virtual Access**: Mounts the image as a virtual disk and uses tools like **FTK Imager Lite** to access its content.
                - Select **FILE -> Image Mounting** to mount the image and access its content from a virtual drive.
                - If permission issues occur, unmount the virtual drive and re-add it as **Add Evidence Item**.
- **Virtual Containers**: Formats used to store cloned data in virtualized environments, allowing access and analysis without working directly on the original device.
    - **VMDK**: VMware virtual disk format.
    - **VHD**: Microsoft Hyper-V virtual disk format.
    - **QCOW**: QEMU format, used in open-source virtualization.
    - **VDI**: Sun VirtualBox format, used in virtualized environments.
    - **EWF/E01**: Expert Witness Format, developed by Guidance Software (EnCASE), used in digital forensics.
    - **AFF**: Advanced Forensic Format, a specialized format for data acquisition.

**Forensic Tools**:

- **Applications**: Programs designed for specific tasks during a forensic investigation, such as evidence collection, data analysis, or system auditing
    - **Belkasoft Live RAM Capturer**: Captures a full image of the RAM, including active user information, running processes, and paged memory.
        - Can extract data from locked systems.
        - Generates a `memoriaRAM.dmp` file that preserves the exact state of the RAM.
    - **Raw Copy**: Open-source tool for copying system-locked files, such as `pagefile.sys`. It operates via command-line and is based on the AutoScript framework.
        - Copies system files in use without disrupting their operation.
        - Example: `Rawcopy64.exe "c:\windows\system32\config\SYSTEM" "c:\users\pesanchez\Desktop"`
    - **Last Activity View**: A NIRSOFT tool for analyzing recent activity in Windows, including executed programs, accessed files, and system logs.
        - Works in both command-line and graphical mode.
        - Generates reports in HTML format, including timestamps of activities.
        - Example: `Lastactivityview /shtml "c:\users\pesanchez\Desktop\report.html"`
    - **WinAudit**: Free and open-source software that performs an in-depth analysis of Windows systems, providing details on hardware, software, and system configurations.
        - Works in both command-line and graphical mode.
        - Generates detailed reports in formats such as text or HTML.
        - Example: `WinAudit.exe /r=gsoPxuTUeERNtnzDaIbMpmidcSArCOHG /f="c:\users\pesanchez\Desktop\report.txt"`
- **Toolkits**: Collections of tools designed for performing multiple complex tasks in forensic investigations, either automated or customized.
    - **PsTools**: A suite of command-line utilities for managing Windows systems, both locally and remotely. It also includes graphical tools like **TCPView**, which displays real-time TCP connections.
        - `PsExec`: Remote process execution.
        - `PsFile`: Displays remotely opened files.
        - `PsGetSid`: Queries locally or remotely connected users.
        - `PsInfo`: Lists detailed system information.
        - `PsKill`: Terminates processes.
        - `PsList`: Provides details on active processes.
        - `PsLoggedOn`: Shows active users on the system.
        - `PsLogList`: Dumps the event log.
        - `PsPasswd`: Changes account passwords.
        - `PsService`: Allows viewing and managing services.
        - `PsShutdown`: Shuts down or restarts computers.
        - `PsSuspend`: Suspends processes.
        - `PsUptime`: Displays system uptime since the last restart.
    - **WMI (Windows Management Instrumentation)**: A set of libraries and functions built into Windows to retrieve system information and manage systems locally or remotely, mainly via commands.
        - Authorizes users/groups and assigns permissions.
        - Configures error logging (only errors or detailed logs).
        - Backs up the repository.
        - Manages services and processes: start, stop, retrieve information, or change configurations.
        - **Comandos:**
            - `wmic bios get serialnumber`: Retrieves the BIOS serial number.
            - `wmic product get name, version`: Displays the name and version of installed programs.
            - `wmic process call create "notepad.exe"`: Launches a process, in this case, Notepad.
            - `wmic process list brief`: Lists active processes in a summarized format.
            - `wmic share list /format:table`: Displays shared resources in table format.
            - `wmic useraccount list brief`: Lists system user accounts in a summarized format.
            - `wmic partition get name, size, type`: Shows partition details: name, size, and type.
    - **OSForensics**: Commercial product for forensic evidence collection and analysis. Includes tools such as Autopsy, Sleuth Kit, Log2timeline, Xplico, and Wireshark.
        - Compatible with Linux, Windows, and macOS.
        - Allows forensic imaging, email analysis, password recovery, and advanced file searches.
        - Features a graphical interface for case management and detailed report generation.
- **Forensic Distributions**: Operating systems designed for digital forensic investigations, preloaded with tools for acquisition, analysis, and evidence preservation.
    - **SIFT (SANS Investigative Forensic Toolkit)**: Free Ubuntu-based forensic distribution developed by SANS. Includes advanced tools such as Autopsy, Sleuth Kit, Volatility, and Log2timeline.
        - Designed for disk, memory, network, and file system analysis.
        - Supports forensic imaging, log analysis, deleted data recovery, and multi-source event correlation.
        - Compatible with image formats like E01, RAW/DD, and AFF, as well as Windows, Linux, and macOS systems.
    - **CAINE (Computer Aided Investigative Environment)**: Linux-based forensic distribution integrating tools like Autopsy, Sleuth Kit, and FTK Imager for file system analysis and data recovery.
        - Provides an intuitive graphical interface for evidence acquisition, analysis, and documentation.
        - Enables forensic imaging of disks and live analysis from a bootable USB.
        - Complies with forensic standards to ensure evidence integrity.
- **Scripting**: Forensic scripts automate evidence acquisition, optimizing data collection and reducing the time required for repetitive tasks.
    - **Requirements for a forensic scripting toolkit**:
        - **Non-intrusive**: Scripts must be documented and tested to avoid interfering with investigated systems.
        - **Reproducibility**: Processes should be replicable in future investigations.
        - **Storage**: Scripts and applications should be stored on an external hard drive with two partitions:
            - **Read-only**: For applications.
            - **Writable**: For storing collected data.
    - **Scripting languages**:
        - **CMD (Windows):** Compatible across all Windows versions, suitable for volatile evidence acquisition.
            - **Example**: Creates dynamic folders and saves system information.
            
            ```
            @echo off
            set USERNAME=%username%
            set COMPUTERNAME=%computername%
            mkdir C:\evidencias\%USERNAME%\%COMPUTERNAME%
            echo "Adquisición de evidencias en progreso..." > C:\evidencias\%USERNAME%\%COMPUTERNAME%\_Processing_Details.txt
            ```
            
        - **VBS (Windows)**: Used since Windows 2000, suitable for evidence acquisition but less powerful than Visual Basic.
            - **Example**: Lists system processes using WMI and saves them to a file.
            
            ```vbnet
            Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
            Set colItems = objWMIService.ExecQuery("Select * from Win32_Process")
            For Each objItem in colItems
                Set objFSO = CreateObject("Scripting.FileSystemObject")
                Set objFile = objFSO.CreateTextFile("C:\evidencias\PROCESOS-SERVICIOS.TXT", True)
                objFile.WriteLine(objItem.Name)
            Next
            ```
            
        - **PowerShell (Windows)**: Pre-installed on Windows 7 and later, ideal for system management and evidence collection.
            - **Example**: Extracts security event logs from the last 24 hours.
            
            ```powershell
            Get-EventLog -LogName Security -Before (Get-Date).AddDays(-1) | more
            Get-EventLog -LogName Security -Before (Get-Date).AddDays(-1) > C:\evidencias\RegistroDeSeguridad.txt
            ```
            
        - **Bash (Linux):** Default scripting language in most Linux distributions, ideal for automation and system management.
            - **Example**: Interactive script allowing the user to select the type of evidence to collect (system info or active processes).
            
            ```bash
            #!/bin/bash
            echo "Seleccione la opción de adquisición de evidencias:"
            echo "1. Información del sistema"
            echo "2. Procesos activos"
            read opcion
            if [ $opcion -eq 1 ]; then
                uname -a > /home/user/evidencias/sistema.txt
            elif [ $opcion -eq 2 ]; then
                ps aux > /home/user/evidencias/procesos.txt
            fi
            ```
            
- **Forensic Analysis Commands:**
    - **Windows**:
        - `netstat`: Displays active network connections, open ports, and protocol statistics, useful for identifying suspicious connections.
        - `ipconfig`: Shows the system’s IP configuration, including IP addresses and subnet masks.
        - `nbtstat -n`: Displays locally registered NetBIOS names, useful for identifying services and associated network names.
        - `arp -a`: Shows the ARP table, mapping IP addresses to MAC addresses, useful for analyzing network devices.
        - `sc query`: Displays the status of system services.
        - `net share`: Lists shared system resources, such as folders or printers.
    - **Linux**
        - `ifconfig eth0`: Displays network configuration details for interface eth0, including IP address and subnet mask.
        - `who -u`: Lists logged-in users and their activity, including terminal used and idle time.
        - `ps -ef`: Shows all running processes in detailed format, including user, PID, and executed commands.
        - `pstree`: Displays running processes in a tree structure, showing hierarchy and relationships.

---

## Windows System Artifacts

**Artifacts:** Digital evidence generated by user interactions with a system, recorded in different OS components.

- Provide details on activities such as application access, file modifications, network connections, and system events.
- Essential in forensic investigations, allowing event reconstruction, user behavior analysis, and detection of unauthorized or malicious actions.

**Key Artifacts:**

- **Downloaded Files:** Evidence generated when users obtain files from the Internet or external sources. Includes records of file locations, timestamps, and storage paths.
    - **Email Attachments:** Files received in emails, such as images, documents, or executables. **Windows 10 Path:** `%USERPROFILE%\AppData\Local\Microsoft\`.
    - **Index.dat (Internet Explorer) / Places.sqlite (Firefox):** Store web browsing activity, visited sites, searches, and downloads. **Windows 10 Path (Index.dat):** `%userprofile%\AppData\Local\Microsoft\Windows\History\Low\History.IE5`.
    - **Downloads.sqlite (Firefox):** Stores Firefox download history, including file name, source URL, timestamp, and download status. **Windows 10 Path:** `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\downloads.sqlite`.
- **Program Execution:** Logs executed programs, including name, execution time, user, and parameters used. Helps identify tools and software used in specific activities.
    - **Prefetch:** `.PF` files storing executed application data, improving performance by preloading required information. Windows 8/10 limits total Prefetch files to 1024. **Windows 10 Path:** `C:\Windows\Prefetch`.
    - **UserAssist:** Records GUI-launched programs, logging names and execution dates. **Windows 10 Path:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`.
    - **Application Compatibility Cache:** Logs compatibility issues, executable details, size, and modification date. Useful for investigating program failures. **Windows 10 Path:** `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`.
    - **Windows Event Log:** Logs events related to program execution, including program name, user, and execution time. **Windows 10 Path:** `C:\Windows\System32\winevt\Logs\`.
- **File Creation & Access:** Logs file creation, modification, and opening, providing key information such as modification dates and authors. Useful for tracking specific activities and file usage patterns.
    - **Jump Lists:** Store recent document and location access via pinned apps in the taskbar or Start menu. **Windows 10 Path:** `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`.
    - **Application Logs (Microsoft Office):** Office apps generate logs when documents are created, modified, or opened, including file name, location, and timestamp. **Windows 10 Path:** `C:\Users\<username>\AppData\Local\Microsoft\Office\`.
    - **MRU (Most Recently Used) Open/Save Files:** Logs recently accessed or saved files, along with the applications used and file paths. **Windows 10 Path:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU`.
    - **LNK Files (Shortcuts):** Auto-generated files when accessing local or remote files, storing original location, access date, and associated applications. **Windows 10 Path:** `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\`.
    - **Windows Event Logs:** Log file creation and access, including user, action performed, and timestamp. **Windows 10 Path:** `C:\Windows\System32\winevt\Logs`.
- **File Deletion:** Logs deleted files, leaving artifacts such as file system entries or memory fragments. Useful for tracking deleted files and detecting evidence-hiding attempts.
    - **Recycle Bin:** Temporarily stores deleted files before permanent removal, recording file name, deletion date, and original path. **Windows 10 Path:** `C:\$Recycle.Bin\<user>\`.
    - **Shadow Copies:** Automatic Windows backups of files and folders, allowing recovery even after deletion. **Windows 10 Path:** `C:\System Volume Information\`.
    - **Thumbnails:** Stores image thumbnails for quick previews, persisting even if the original images are deleted. **Windows 10 Path:** `C:\Users\username\AppData\Local\Microsoft\Windows\Explorer\`.
    - **Windows Event Log:** Records file deletion events, including timestamp, user, and performed action. **Windows 10 Path:** `C:\Windows\System32\winevt\Logs\`.
- **Physical Location:** Logs device and data locations, essential for tracking storage devices in forensic investigations.
    - **TimeZone:** Records the system’s configured time zone, useful for correlating events across different time zones. **Windows 10 Path:** `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`.
    - **Network Logs:** Store information on connected networks, including SSID, MAC address, and domain name, helping track locations through network connections. **Windows 10 Paths**: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged`   `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed`   `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`
- **USB & Devices:** Logs interactions with external storage devices such as USB drives, hard drives, and peripherals. Critical for tracking data access in forensic investigations.
    - **USB Device Logs:** Stores information on connected USB devices, including name, connection date, and unique ID. **Windows 10 Path:** `SYSTEM\CurrentControlSet\Enum\USB\` `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\`
    - **First/Last Use:** Logs first and last connection timestamps for USB devices. **Windows 10 Path:** `C:\Windows\inf\setupapi.dev.log`.
    - **Drive Letter & Volume Name:** Records the drive letter assigned to USB devices along with volume name. **Windows 10 Path**: `SOFTWARE\Microsoft\Windows Portable Devices\Devices` `SYSTEM\MountedDevices`
    - **Plug & Play Event Log**: Records events related to Plug & Play device installation, including USB devices. **Windows 10 Path:** `%systemroot%\System32\winevt\logs\System.evtx`
- **User Accounts:** Logs access, creation, modification, deletion, and user actions. Crucial for tracking system activity and detecting unauthorized behavior.
    - **Login & Account Audit Logs:** Record login attempts, timestamps, usernames, IP addresses, and success/failure status. Also logs security-related events such as password policy changes and account lockouts. **Windows 10 Path:** `C:\Windows\System32\winevt\Logs\Security.evtx`.
    - **User Accounts:** Logs creation, modification, and deletion of user accounts, including password changes and assigned privileges. **Windows 10 Path:** `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`.
    - **Stored Credentials:** Stores locally saved login credentials (usernames and passwords) in Windows Credential Manager. **Windows 10 Path:** `C:\Users\<username>\AppData\Local\Microsoft\Credentials\`.
- **Browser Usage:** Logs web browsing activity, including visited sites, searches, cookies, and cache. Helps reconstruct user behavior in forensic investigations.
    - **Browsing History:** Stores visited websites along with timestamps.
        - **Edge**: `%userprofile%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat`
        - **Chrome**: `%userprofile%\AppData\Local\Google\Chrome\UserData\Default\History`
        - **Firefox**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\places.sqlite`
    - **Cache:** Stores webpage components for faster loading.
        - **Edge**: `%userprofile%\AppData\Local\Packages\microsoft.microsoftedge_<APPID>\AC\MicrosoftEdge\Cache`
        - **Chrome**: `%userprofile%\AppData\Local\Google\Chrome\User Data\Default\Cache\ -data_# and f_######`
        - **Firefox**: `%userprofile%\AppData\Local\Mozilla\Firefox\Profiles\<randomtext>.default\Cache`
    - **Cookies**: Stores visited website data, including authentication details and preferences.
        - **Edge**: `%userprofile%\AppData\Local\Microsoft\Edge\User Data\Default\Cookies`
        - **Firefox**: `userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\cookies.sqlite`
        - **Chrome**: `%userprofile%\AppData\Local\Google\Chrome\UserData\Default\LocalStorage`

**Windows Registry**: A centralized database that stores operating system configurations, hardware settings, installed software, user preferences, and other essential system details.

- **Hierarchical Structure**: Functions similarly to a file system, with keys and subkeys containing values. These keys store software configurations, user profiles, system parameters, and device settings.
- **Main Sections:**
    - **HKEY_CLASSES_ROOT (HKCR)**: Contains file association information, specifying which programs can open certain file types.
    - **HKEY_CURRENT_USER (HKCU)**: Stores user-specific settings such as profiles, preferences, and application configurations.
    - **HKEY_LOCAL_MACHINE (HKLM)**: Holds hardware details, system settings, and installed applications.
    - **HKEY_USERS (HKU)**: Stores configuration data for all user profiles on the system.
    - **HKEY_CURRENT_CONFIG (HKCC)**: Maintains current hardware configuration and profile settings.
- **Registry Hive Files**: Data files where registry information is stored and continuously accessed by the operating system.
    - **HKEY_LOCAL_MACHINE\SAM**: Stores passwords and user account configurations. **Files:** `Sam`, `Sam.log`, `Sam.sav`.
    - **HKEY_LOCAL_MACHINE\Security**: Contains security-related system configurations. **Files:** `Security`, `Security.log`, `Security.sav`.
    - **HKEY_LOCAL_MACHINE\Software**: Stores software application data and configuration settings. **Files:** `Software`, `Software.log`, `Software.sav`.
    - **HKEY_LOCAL_MACHINE\System**: Includes system settings and boot configurations. **Files:** `System`, `System.alt`, `System.log`, `System.sav`.
    - **HKEY_CURRENT_CONFIG**: Holds hardware profile information used during system startup. **Files:** `System`, `System.alt`, `System.log`, `System.sav`, `Ntuser.dat`, `Ntuser.dat.log`.
    - **HKEY_USERS\DEFAULT**: Stores default settings for new users. **Files:** `Default`, `Default.log`, `Default.sav`.

**Windows Registry Analysis:**

- **Online Analysis:**
    - Allows real-time system status review.
    - **Methods:** Data extraction, key export, file comparison.
    - **Advantage:** Immediate access to user activities and configurations.
    - **Precaution:** Risk of alterations if the system is compromised or running.
- **Offline Analysis:**
    - Crucial when dealing with malware (e.g., rootkits) that may manipulate data.
    - Requires copies of registry files to prevent modifications during analysis.
    - **Offline Analysis Tools:**
        - **RegRipper:**
            - Modular plugin-based structure for fast, scalable analysis.
            - Extracts relevant keys using predefined patterns and generates detailed reports with timestamps.
        - **Windows Registry Recovery:**
            - Graphical tool for easy data extraction and review.
            - Ideal for preliminary analysis or non-advanced investigations.

**Windows Event Viewer:** A built-in Windows tool that logs system, application, and security events. Each event includes details like date, time, severity level (info, warning, error), and event description.

- Primarily used for system monitoring and troubleshooting, but also essential for forensic investigations and security auditing.
- **Logs:**
    - **Windows Logs:** Organized into five subcategories:
        - **Application:** Events from system applications, useful for diagnosing software failures.
        - **Setup:** Tracks installation or updates of applications/services, useful for verifying installation timelines.
        - **Security:** Logs security events, such as login attempts, security setting changes, and permission audits. Critical for forensic analysis and unauthorized access detection.
        - **System:** Logs OS and hardware driver events, including system failures and performance warnings.
        - **Forwarded Events:** Gathers logs from remote machines via subscriptions.
    - **Applications and Services Logs:** Categorized into four subtypes:
        - **Administrative:** System management events, mainly for troubleshooting.
        - **Operational:** Monitors applications/services to detect failures or performance issues.
        - **Analytical:** Provides in-depth monitoring, requiring additional tools for interpretation.
        - **Debug:** Tracks software component errors for development and debugging purposes.
    - **Access:** Through Event Viewer (`eventvwr.msc`), Control Panel, or CMD.
    - **Real-Time Monitoring:** Allows event observation as they occur.
    - **Navigation:** Events can be filtered, sorted, and searched based on criteria such as date or event type.

**Prefetch**: A Windows directory that stores files optimizing application and process startup performance.

- **Function:** Works as a cache memory for frequently accessed system files and applications.
- **Content:** `.PF` files containing:
    - Disk information and serial number.
    - Last execution date and time.
    - Execution frequency.
    - Forensic data on executed applications.
- **Process:** When a program runs, **Windows Cache Manager** generates a `.PF` file with the format `program-HASH.pf`, where the hash is a unique identifier based on the program's full path.
- **Registry Key:** Prefetch settings are stored in: `HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\MemoryManagement\PrefetchParameters`
- **Key Tool:**
    - **WinPrefetchView:** Parses `.PF` files for forensic investigations, malware detection, and tracking software execution. [http://www.nirsoft.net/utils/win_prefetch_view.html](http://www.nirsoft.net/utils/win_prefetch_view.html)

---

## Network Forensics Analysis

**Packet and Protocol Analysis Tools:** Software designed to capture, analyze, and display network traffic, aiding in packet inspection, communication troubleshooting, and threat detection. These tools help monitor real-time network behavior and diagnose anomalies.

- **Key Aspects:**
    - **Supported Protocols:** Compatibility with common protocols (SMTP, DHCP, DNS, HTTP) and interpretation of less common ones.
    - **Scalability:** Ability to handle large, complex networks.
    - **Automation:** Support for scripting and command-line operations.
    - **Functionality & Architecture:** Evaluates network impact for optimal performance.
    - **Technical Support:** Assistance availability for troubleshooting and optimization.
- **Process Stages:**
    1. **Collection:** Captures traffic using network card **promiscuous mode** or specialized devices.
    2. **Interpretation:** Organizes and translates captured packets into readable data.
    3. **Presentation:** Decodes and analyzes frames based on protocol knowledge, displaying key information.
- **Traffic Collection Methods:** Choice depends on network architecture and available hardware.
    - **Port Mirroring:** Switch configuration to replicate traffic to a specific port where the capture tool is connected.
    - **Network TAP (Test Access Point):** A Layer 1 OSI device that copies traffic directly from network cabling without affecting network performance, ensuring security.

**Examples of Packet and Protocol Analysis Tools:**

- **Ettercap:**
    - Designed for analyzing switched networks.
    - Supports both active and passive protocol analysis.
    - Enables **Man-in-the-Middle (MitM) attacks**, useful for penetration testing and vulnerability assessment.
- **Kismet:**
    - Wireless network analyzer and intrusion detection tool for **802.11 networks**.
    - Detects hidden SSIDs, unauthorized access points, and wireless network vulnerabilities.
- **TCPDump:**
    - Command-line tool for capturing and analyzing real-time traffic.
    - Displays packets sent and received, useful for quick inspections and scripting.
- **Wireshark**: A powerful and versatile packet capture and analysis tool, compatible with **Linux** and **Windows**. Ideal for **network auditing** and **traffic diagnostics**.
    - **Real-Time Capture:** Essential for network monitoring and issue detection.
    - **Interface Selection:** Allows choosing the capture interface. Wireless interfaces can enable **promiscuous mode** to capture all network traffic, not just directed packets.
    - **Packet Analysis:** Captures can be stopped once sufficient data is collected. Uses **color coding** to differentiate packet types.
    - **Packet Details:** Displays packet breakdown, including **source/destination IPs, protocol, length**, and content summary. Analyzes packets per **OSI layers** for in-depth inspection.
    - **Filters:** Helps manage large data volumes by filtering specific protocols (**HTTP, TCP, ARP**). Custom filters can be created via **Analyze -> Display Filters**.
    - **Connection Tracking:** The **Follow TCP Stream** feature reconstructs communication between two hosts, useful for file recovery and forensic investigations.
    - **Statistics and Graphs:** Provides real-time traffic insights through the **Statistics** tab.
        - **Protocol Hierarchy:** Displays packet distribution by protocol type.
        - **Flow Graph:** Visually represents **TCP interactions** or overall network traffic.
    - **File Exporting:** Captured objects (e.g., **HTTP files**) can be exported for further analysis (**File -> Export Objects -> HTTP**).
- **NetworkMiner:** A **Windows-based forensic analysis tool** that extracts and processes network capture files, providing details on applications, operating systems, transferred files, open connections, credentials, and sessions.
    - **Offline Analysis:** Allows importing **PCAP files** for examining previously captured traffic.
    - **File Recovery:** Reconstructs **transferred files**, useful for retrieving lost data.
    - **Malware Traffic Analysis:** Detects malicious behaviors in network traffic.
    - **Credential Discovery:** Extracts **usernames and passwords** from captured data using the **Credentials** tab, aiding in unauthorized access detection.
- **Xplico**: Graphical tool for analyzing network captures that handle large volumes of data and protocols. Useful for examining dynamic activities, such as malicious code.
    - **PCAP File Support**: Works with captures in PCAP format and supports real-time traffic.
    - **Protocol and Content Analysis**: Extracts information such as web activities, DNS, emails, chats, images, and more.
    - **Malware Analysis**: Identifies threats in traffic generated by malicious code.

---

## Implementing Intrusion Prevention

**IDS (Intrusion Detection System)**: A system that **monitors networks or hosts** to detect suspicious activities or intrusions by analyzing traffic for attack patterns or signatures. It generates alerts for unusual behavior but does not actively intervene in traffic, leaving the response to administrators.

**IPS (Intrusion Prevention System)**: A system that **actively monitors and prevents intrusions**. It can block malicious traffic, reset connections, and adjust security configurations (e.g., firewalls) in real-time to protect infrastructure from attacks.

- **Types of IPS Based on Functionality**
    - **NIPS (Network IPS):**
        - Monitors network activity by comparing data with **known threats or normal patterns**.
        - Installed **between firewalls and servers** (or any protected element) to provide visibility over all network traffic.
    - **WIPS (Wireless IPS)**
        - Detects **unauthorized activity** in wireless networks by analyzing protocols and validating **MAC addresses** of access points against known signatures.
        - **Implementation Methods:**
            - **Time Sharing:** Alternates between **ensuring connectivity** and **periodically scanning** for rogue access points.
            - **Integrated WIPS:** Sensors in **authorized access points** continuously scan wireless signals for rogue devices.
            - **Overlay WIPS:** Dedicated **sensors deployed throughout the infrastructure** monitor wireless signals and send data to a central server for analysis and protection. This is the most **effective but costly** approach.
        - **Components:**
            - **Sensors:** Monitor radio frequencies and send logs to the **central server**.
            - **Central Server:** Analyzes sensor data and takes **protective actions**.
            - **Database Server:** Stores captured data for further **analysis**.
            - **Console:** Interface for managing and implementing **WIPS policies**.
    - **NBA (Network Behavior Analysis)**
        - Analyzes **network behavior** by collecting data from access points and connected devices.
        - Identifies **normal, unusual, and potentially malicious** activity.
        - Monitors **bandwidth changes and protocol variations**, helping detect threats.
    - **HIPS (Host IPS)**
        - **Installed directly on hosts** to protect them by monitoring OS activity, logs, files, and system resources.
        - Combines features of **antivirus, behavior analysis, and network/application firewalls**.
        - Detects attacks by **intercepting unvalidated interactions** with the OS or applications.

**False positives**: Both **IDS** and **IPS** can generate **false positives**, especially during the initial configuration phase, when legitimate activities are mistakenly identified as suspicious, leading to erroneous alerts.

- **IDS (Intrusion Detection System):** As it is passive, **false positives** do not directly affect network traffic. However, they generate unnecessary alerts, increasing the workload and distracting from real incidents.
- **IPS (Intrusion Prevention System):** Since it is reactive, **false positives** can lead to blocking legitimate traffic, resetting valid connections, or altering security configurations, which can impact **network availability** and **user experience**.
- **Reducing False Positives:**
    - **Initial and Ongoing Tuning:** Involves adjusting thresholds and rules based on the **environment's behavior**, iteratively refining parameters and maintaining continuous monitoring to minimize false positives.
    - **Machine Learning:** Some modern systems integrate **machine learning** to enhance accuracy by adapting to normal traffic patterns over time.
    - **Staff Training:** Analysts need training to **correctly identify and classify alerts**, reducing the chances of incorrect responses.
    - **Balance:** While it is impossible to eliminate **false positives** entirely, it is crucial to find a balance that ensures **environment protection** without excessively disrupting normal operations, maximizing the system's effectiveness.

**Intrusion Detection Methods:**

- **Signature-based Detection:** Compares network traffic with signatures of known attacks. If a match is found with a predefined signature, the system may block malicious traffic.
- **Anomaly-based Detection (Statistical):** Establishes a baseline of normal traffic and alerts when activities deviate from this reference. **False positives** can occur if the baseline is not properly adjusted.
- **Stateful Protocol Analysis Detection:** Analyzes communication protocols and compares suspicious events with profiles of malicious behavior, helping to identify intrusions by validating protocols.

**Snort**: An open-source Intrusion Detection and Prevention System (IDPS) that uses rules to identify and alert on malicious activity in the network.

- **Features:**
    - **Intrusion Detection:** Captures and analyzes packets in TCP/IP networks, functioning as a real-time detection system or sniffer in small networks.
    - **Malicious Traffic Detection:** Passively monitors network traffic, sending data to database servers or logs for analysis.
    - **Real-Time Alerts:** Generates instant notifications on detected attacks and intrusions.
    - **Database Notifications:** Allows alert reporting to database managers (MySQL, PostgreSQL) and traffic analysis using preprocessors before comparing it to rules for detection.
    - **Compatibility and Availability:** Free, compatible with Windows and UNIX/Linux, under GPL license, with predefined filters and constant updates to address new attacks.
- **Architecture:**
    - **Packet Decoder:** Captures traffic and prepares it for analysis.
    - **Preprocessor:** Examines captured packets using plugins to identify suspicious behaviors.
    - **Detection Engine:** Compares packets with a rule base that describes known attacks, generating alerts if matches are found.
    - **Alert and Reporting System:** Produces detailed reports on analyzed traffic, with statistics and alerts about suspicious activities.

**FireEye Network Security:** A modular solution that protects against advanced cyberattacks and hidden threats.

- **Added Value:** By combining different technologies:
    - Detects advanced threats, both known and unknown.
    - Complements traditional defense systems.
    - Generates precise alerts through data correlation.
- **Main Components:**
    - **MVX (Dynamic Analysis Engine):** Dynamically analyzes network traffic and files to identify unknown threats without relying on signatures.
    - **IDA (Intelligence-Driven Analysis):** Uses rules and threat intelligence to detect malicious patterns in traffic.
    - **IPS (Intrusion Prevention System):** Detects and blocks common attacks through signature-based detection.
    - **Threat Intelligence Integration:** Correlates data from FireEye with external threat sources, providing a comprehensive view of risks.
    - **SmartVision:** Identifies lateral traffic within the network, detecting suspicious movements of attackers.
- **Implementation and Availability:**
    - Installed in the internet traffic path, typically behind firewalls, traditional IPS systems, and secure web gateways, complementing them.
    - Compatible with Linux, Windows, and macOS, with flexible deployment options to adapt to various organizational needs.

---

## Email Forensics

**Email Application Modalities:**

- **Email Client:** An application installed on devices (computers, tablets, smartphones) for managing emails. It allows downloading messages to the device or keeping them on the server using protocols such as IMAP.
    - **Examples:** Mozilla Thunderbird, Outlook.
- **Webmail:** Access to email through a browser, with all messages stored on the server. It doesn't require additional program installation and offers a simple interface for managing emails from any device with an internet connection.

**X400 Protocol:** International standard for email exchange, developed by ISO.

- **Personalization:** Uses unique electronic mailboxes to precisely identify users, allowing greater personalization in communications.
- **Message Storage:** Messages are stored until viewed by the user, allowing some control over the delivery and reception of emails.
- **Limitations:** Although reliable in its time, X400 was never widely adopted due to the flexibility and ease of implementation of SMTP, and its use has decreased over time.

**SMTP (Simple Mail Transfer Protocol):** The most commonly used standard protocol for sending emails.

- **Sending Emails:** SMTP handles the sending of messages between email servers, while protocols such as **POP3** or **IMAP** manage the reception and storage.
- **Evolution with the Web:** Initially used only for communications between email servers, it has now been integrated with **MAPI** (for Exchange) and **HTTP-based** technologies to facilitate access in web and mobile clients.
- **Limitations:** It doesn't provide encryption by itself, which led to protocols like **SMTPS** and **STARTTLS** to encrypt email transmissions.
- **ESMTP (Extended SMTP):** Introduces improvements and new functionalities, allowing email clients to query the server to see if it supports certain extensions.
    - To check if a server supports ESMTP, the client sends the EHLO command, and if supported, the server responds with the available extensions; otherwise, it returns a 500 error.

**Email headers:**

- **FROM (Sender):** The sender's address, which can be altered, making it less reliable.
- **SUBJECT (Subject):** A brief description of the email's content.
- **DATE (Date):** The date and time the email was sent.
- **TO (Recipient):** The recipient's address, which may not appear in some cases.
- **REPLY-TO:** The address used for handling email bouncebacks, located above the "Received" header, which shows the sender's public IP.
- **Server Fields:** Parameters for communication between the email server and client, not visible to the sender or recipient.
- **RECEIVED:** Shows the chain of servers the email passed through, with the IPs and authentication protocols (DMARC, DKIM, SPF).
- **Message-ID:** A unique identifier for the email, which is susceptible to modification.
- **MIME (Multipurpose Internet Mail Extensions):** A standard that extends message types (text, images, binaries) for sending via SMTP.
- **Content-Type:** Specifies the format of the message (HTML, plain text, etc.).
- **Spam Score:** The spam score generated by the email service or client.
- **Message Body:** The actual content of the email, written and sent by the sender.

**MIME (Multipurpose Internet Mail Extensions):** A standard that extends email capabilities, allowing the inclusion of documents in messages. It uses BASE64 to encode complex files into ASCII data, making it compatible with nearly all current applications.

- **S/MIME (Secure MIME):** An extension of MIME that supports message encryption using RSA public key cryptography, ensuring confidentiality during transit and storage.
- **MIME Features:**
    - Allows the use of rich text (colors, fonts, etc.).
    - Supports non-ASCII character sets.
    - Extends the message without limitation.
    - Enables sending multiple attachments, even binary files, and allows splitting them if needed.
- **Primary MIME Types:** Categories used to classify email content or web documents, specified in "Content-Type." The goal is for the receiver to process them correctly:
    - **text/plain:** Plain text.
    - **text/html:** HTML-formatted text.
    - **image/jpeg, image/png, image/gif:** Images in their respective formats.
    - **application/pdf, application/zip, application/json:** PDF, ZIP, or JSON files.
    - **audio/mpeg, video/mp4:** MP3 audio files and MP4 video files.
    - **multipart/mixed:** Messages with multiple attachments (e.g., text and image).
    - **multipart/alternative:** Messages with alternative versions (plain text and HTML).

**SMTP commands:** These commands allow interaction with the server to manage the sending and delivery of messages:

- **HELO:** The client identifies itself to the SMTP server and initiates the conversation.
- **MAIL FROM:** Specifies the sender's address and starts a new message.
- **RCPT TO:** Specifies the recipient's address. It can be repeated for multiple recipients.
- **DATA:** Begins the transfer of the message body and attachments. The server responds with code 354 to indicate it can receive the data.
- **RSET:** Aborts the current email transfer, discarding the information without closing the connection.
- **VRFY:** Verifies the existence of a mailbox on the server. Often disabled in servers like Exchange.
- **QUIT:** Requests the connection to be closed. The server responds with code 221 and terminates the session.

---

## Windows Log Management and Analysis

**Important Log Files for Forensic Analysis:**

- **Files in %WINDIR%\:**
    - **Setupact.log:** Records actions during program installations (dates, paths, installation disks).
    - **setuperr.log:** Contains installation errors and program failures.
    - **WindowsUpdate.log:** Logs system and application update information.
    - **Debug\mrt.log:** Details of malware removal (date, version, and activity).
    - **SoftwareDistribution\ReportingEvents.log:** Logs events related to installations, downloads, and update packages.
    - **Logs\CBS\CBS.log:** Details about Windows Resource Protection files not restored, processes, and boot dates.
    - **INF\setupapi.dev:** Logs device and driver installations, and potential signing issues.
    - **INF\setupapi.setup:** Contains system and application installation information.
    - **Performance\Winsat\winsat.log:** Records performance test results using the Windows Performance Toolkit.
    - **Performance\Winsat\winsat.log\INI:** Contains program configuration data (paths, user parameters).
    - **Memory.dmp:** Saves memory dumps, including accesses, memory addresses, and users.
- **Files in Other Directories:**
    - **%AppData%\setupapi.setup:** Logs information about drives, service packs, and system/Bios details.
    - **%SYSTEMROOT%$Windows.~BT\Sources\Panther.log.xmland %WINDIR%\PANTHER.log.xml:** **Provides information about errors and devices after a failed update.

**Volume Shadow Copy (VSC):** Service that creates system backups and restores them in case of failures. Copies are automatically generated when changes occur, like installations or updates, and remain hidden within the file system.

- These copies are vulnerable to ransomware that may delete them.
- **Vssadmin:** A console tool to manage and view backups. The command `vssadmin list shadows` shows existing snapshots.
- **Mklink:** Used to create symbolic links to directories, files, or directory junctions.
- **Other Tools:** The Sleuth Kit (Autopsy) and VSC Toolset are tools that allow exploration of hidden volumes with graphical interfaces, though some require administrator permissions.