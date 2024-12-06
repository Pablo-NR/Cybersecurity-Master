# 2. Ethical Hacking

## Audits

**Key terms:**

- **Hacker (Good)**: Cybersecurity expert who enhances infrastructures and protects systems, constantly learning about new technologies.
- **Cracker (Bad)**: Exploits vulnerabilities for malicious purposes, driven by profit or challenge.
- **Ethical Hacker**: Conducts audits and penetration tests to identify and fix vulnerabilities legally.
- **White Hat**: Uses their skills to protect systems legally and ethically.
- **Black Hat**: Uses their knowledge for illegal and destructive purposes.
- **Grey Hat**: Employs both legal and malicious techniques depending on personal interest.
- **Hacktivism**: Hacking used to promote social, political, or human rights causes.
- **Pirate**: Illegally accesses systems or networks to steal or destroy data.
- **Backdoor**: Hidden access to a compromised system, used by an attacker for remote control.

**Security Audit**: Systematic and thorough review simulating a real attack to identify risks that may impact the business. The fewer restrictions imposed, the more comprehensive the analysis, uncovering more technical vulnerabilities and business risks.

**Vulnerability Scanning**: Brief and automated process aimed at detecting specific vulnerabilities in systems and applications. It does not simulate a real attack but focuses on identifying potential technical flaws without assessing their business impact.

**Security Frameworks**: Structured methodologies that guide the security evaluation process across various areas (infrastructure, web, and mobile applications).

- **PTES**: Focuses on penetration tests, from initial interactions to the final report.
- **OSSTMM**: Comprehensive methodology covering multiple aspects of organizational security.
- **Penetration Testing Framework**: Exclusively focused on penetration testing.
- **OWASP Testing Framework**: Specializes in web application security.
- **NIST 800-115**: Guide for penetration testing, covering planning through reporting.

**Distributions for Auditing:** Linux distributions preconfigured with tools for penetration testing, forensic analysis, and security assessments of networks, applications, and systems, providing a ready-to-use environment for controlled attacks and vulnerability evaluations.

- **Kali Linux**: The most widely used, with 600+ ethical hacking tools.
- **Parrot Security**: Similar to Kali, with additional tools and a focus on privacy.
- **DEFT Linux**: Specializes in forensic analysis.
- **BackBox Linux**: Ubuntu-based, ideal for pentesting and security assessment.
- **BlackArch Linux**: One of the most extensive, with 2000+ tools aimed at security researchers.

**Types of Audits by Approach:**

- **External Pentest**: Assesses the security of internet-exposed systems, perimeter, and DMZ, aiming to identify vulnerabilities and attempt access to the internal network.
- **Internal Pentest**: Simulates attacks from the perspective of an internal user with limited privileges, evaluating privilege escalation and compromise of critical assets.
- **Red Team**: Simulates advanced attacks to measure the organization’s detection, response, and resilience against real threats.

**Types of Audits by Information Provided:**

- **Black Box**: Simulates a real attack; the auditor only knows the organization’s identity, without internal information.
- **Grey Box**: The auditor has partial access to the infrastructure, facilitating specific tasks and allowing for deeper evaluation.
- **White Box**: The auditor has full access to internal information, such as network maps, skipping the fingerprinting phase.

---

## Reconnaissance Phase

**Reconnaissance Phase:** First phase of an audit, focused on gathering target information to identify attack vectors. Includes OSINT to collect public data without directly interacting with the target.

**Two parts:**

1. **Passive Reconnaissance (Footprinting):** Gathering information through public sources only, with no direct, detectable interactions with the target. Collects details such as exposed services, applications, emails, user accounts, and employees.
    - **Google Dorks**: Advanced Google queries to locate sensitive information or vulnerabilities on websites.
    - **E-mail Harvesting**: Collecting employee email addresses for targeted attacks or user mapping. **The Harvester**, a tool in Kali, searches for emails across multiple search engines.
    - **Whois**: Queries the Whois database to identify domains, servers, IPs, and contacts associated with the organization.
2. **Active Reconnaissance (fingerprinting)**: Collecting detailed information through active scans (ports, machine enumeration), generating detectable traffic. Identifies vulnerabilities, assets, servers, and exposed directories.
    - **DNS Enumeration:** Obtaining domains, subdomains, IPs, and DNS/mail servers through DNS queries.
    - **SMB Enumeration (Server Message Block):** Identifying SMB services (ports 139, 445) for resource sharing. Includes NULL sessions, where unauthenticated users access basic information.
    - **SMTP Enumeration:** Using misconfigured mail servers to execute commands like *VRFY* or *EXPN*, verifying users on a mail server.
    - **SNMP Enumeration (Simple Network Management Protocol):** UDP-based protocol for exchanging information between network devices. Attackers can gather device details (name, OS, manufacturer), network functions (IP, subnet), and active users/processes if connected to SNMP.

## Scanning Phase

**Scanning Phase**: Second phase of the audit, focused on detailing network infrastructure, operating systems, services, and their versions. Its goal is to identify vulnerabilities and gather data to apply specific techniques for evaluating the target.

**Types of Scanning Based on Attacker Position:**

- **Internal Scanning:** Analysis from within the target network, exploring internal services like Active Directory, accounting systems, or internal controls that are inaccessible externally.
- **External Scanning:** Evaluation of the perimeter accessible from the internet, including public services such as web, email, or intranet, to identify exposed resources.

**Types of Scanning Based on the Target:**

- **Network Scanning:** Identifies the target’s structure, including IP addressing, network segments, and internal visibility.
    - **Host Discovery with ICMP:** Sends pings to an IP range to detect active hosts through ICMP responses. Effective for internal and external networks.
        - **Tools:** Hping3, Nmap (also for ports and services), and Zenmap (Nmap’s graphical version).
    - **Host Discovery with ARP:** ARP protocol links an IP (layer 3) with an Ethernet address (layer 2), identifying the interface for sending packets. ARP Discovery messages broadcast on the internal network ask for specific IPs; only the host with that IP responds, revealing active IPs.
        - **Tools:** Arp-scan and Netdiscover for quick internal network scans.
    - **Device and Network Configuration Discovery:** Identifies devices like routers and switches, mapping network topology to assist in later phases.
        - **Tools**:
            - **Traceroute:** Tracks routes to destinations using ICMP.
            - **Wireshark:** Captures and analyzes traffic for network details.
            - **Nmap:** Can detect host operating systems.
- **Service Scanning:** Identifies open TCP/UDP ports and associated services, detailing active versions and technologies for potential exploitation.
    1. **Port Enumeration:** Identifies open ports through direct communication and response analysis using **Nmap**.
        - **TCP Scanning:** Nmap sends a SYN to a port, with three possible outcomes:
            - **Open Port:** SYN/ACK response.
            - **Closed Port:** RST (Reset) response.
            - **Filtered Port:** No response, indicating a firewall.
        - **SYN Scanning:** Sends a SYN and ends with RST after receiving SYN/ACK, avoiding full connections for speed and IDS evasion.
            - Closed and filtered ports respond the same as in TCP scanning.
        - **UDP Scanning:** Slower due to fewer responses.
            - **Open or Filtered Port:** No response.
            - **Closed Port:** Ping with "port unreachable" message.
        - **Xmas, FIN, NULL Scans:** Stealthy methods to evade firewalls and IDS.
    2. **Service and Version Enumeration:** Identifies active services on open ports, along with their technology and versions. Main tools:
        - **Nmap -sV:** Detects services and versions.
        - **Nmap -A:** Detects services, versions, OS, performs traceroute, and runs advanced scripts.
        - **Version Scripts:** Provide additional details on specific services.
- **Vulnerability Scanning:** Searches for known vulnerabilities in detected services and versions, evaluating entry points based on their exploitability.
    - **Key Concepts**:
        - **CVE:** List of known security vulnerabilities.
        - **0-day:** Unknown vulnerability exploited before being reported or patched.
    - **Nmap:** Scripts from the "**Vuln**" category detect known vulnerabilities based on service types and versions. **Vulscan** queries databases like CVE or Exploit-DB.
    - **Nessus:** Popular vulnerability scanning tool with advanced options for customized scans and report generation.
    - **Specialized Scanners:**
        - **Sslscan** and **Testssl:** Identify vulnerabilities in TLS/SSL protocols.
        - **Wpscan** and **JoomScan:** Detect issues in CMS like WordPress and Joomla.
        - **Qualys Web-app** and **Acunetix:** Analyze web applications to discover both known and unknown vulnerabilities.
    - **Open Vulnerability Sources:** Platforms like **CVE Mitre**, **Security Focus**, **Exploit-DB**, **Security Tracker**, and **OpenVAS** provide updated information on vulnerabilities, exploits, PoCs, and patches.

### Nmap: Advanced Scanning

**IP and Port Ranges:**

- **CIDR Notation:** Define IP range using CIDR. `nmap 192.168.1.0/24`
- **Regular Expressions:** Target by patterns. `nmap 192.168.1.*`
- **Consecutive IP Range:** `nmap 192.168.1.1-40`
- **Hostname:** Resolves and scans a host. `nmap www.microsoft.com`
- **Specific Port Range:** `nmap 192.168.1.1 -p 1-1024`
- **Specific Ports:** `nmap 192.168.1.1 -p 80,443`
- **Most Common Ports:** `nmap 192.168.1.1 --top-ports=100`
- **Option Combination:** Mix IP ranges, CIDR, and ports. `nmap 192.168.1.201-254 -p 80,443,8000-9000`

**Input Files and Exporting Results:**

- **Input File (-iL):** Reads targets from a file. `nmap -iL host_445-up.txt -p 445`
- **Save in Standard Format (.nmap):** `nmap 192.168.1.1 -oN result`
- **Save in Grepable Format (.gnmap):** `nmap 192.168.1.1 -oG result`
- **Save in XML Format (.xml):** `nmap 192.168.1.1 -oX result`
- **Save in All Formats (-oA):** `nmap 192.168.1.1 -oA result`

**Scan Speed (-T):**

- **From Slow to Fast:** `T0` → `T1` → `T2` → `T3` → `T4` → `T5`

 ****

**Advanced Script Usage (NSE Scripts):**

- **List Available Scripts:** `nmap --script-help all`
- **Run Specific Script:** `nmap 192.168.15.205 --script <script-name>`
- **Run Scripts by Protocol:** `nmap 192.168.15.205 --script "smb-*"`
- **Run Common Scripts on Open Ports:** `nmap 192.168.15.205 -p 1-65535 -sC`

**Script Categories:**

- **Run All Scripts in a Category:** `-script <category>`
- **Combine Categories:** Use `and`, `or`, `not`.
    - **Auth:** Bypass or use known credentials.
    - **Broadcast:** Discover new hosts on the network.
    - **Brute:** Test passwords across protocols.
    - **Default:** Default scripts with `sC` or `A`.
    - **Discovery:** Collect additional host information (SNMP, directories).
    - **Dos:** DoS testing.
    - **Exploit:** Attempt to run exploits.
    - **Fuzzer:** Perform fuzzing on protocols.
    - **Intrusive:** High-impact scripts that may harm the system.
    - **Malware:** Detect malware signs.
    - **Safe:** Non-intrusive scripts without negative effects.
    - **Version:** Detect service/protocol versions.
    - **Vuln:** Identify known vulnerabilities.

---

## Exploitation Phase

**Exploitation Phase**: Third phase of the audit, where discovered vulnerabilities are leveraged to gain unauthorized access to a system or perform malicious actions.

- **Attack vectors**: Common methods attackers use to infiltrate a network or system:
    - Social engineering and phishing
    - Credential theft and weak passwords
    - Unpatched vulnerabilities
    - Misconfigured or default service settings

**An Exploit Has Two Components:**

- **Exploit:** Code designed to take advantage of a vulnerability by executing unauthorized instructions. It is the mechanism that grants access to a vulnerable system or device.
- **Payload:** Actions executed after gaining access via the exploit. These include privilege escalation, data theft, or running commands within the compromised system.

**Exploit Categories:**

- **Service-side:** Target server-side services like Apache or Nginx.
- **Client-side:** Exploit client-side software like browsers or email applications.
- **Local Privilege Escalation (PoE):** Locally executed exploits to gain elevated privileges on a system.

**Finding Exploits:**

- **SearchSploit:** Linux tool that searches a local Exploit-DB database.
- **Exploit-DB and 0day.today:** Online databases offering a wide range of exploits, including remote and local vulnerabilities.

**Shellcode:** Set of instructions designed to execute a specific action after exploiting a vulnerability. Its primary goal is to launch a "shell" or command-line interface, allowing the attacker to control the system.

- **Types of Shellcode by Attacker's Access Level:**
    - **Local Shellcode:** Used when the attacker already has system access and exploits a vulnerability to escalate privileges within the same system.
    - **Remote Shellcode:** Executed on a different machine, typically over a network, to gain remote control of the target system.
- **Shellcode Types by Victim-Attacker Connection:**
    - **Bind Shell:** Opens a port on the victim’s machine, allowing the attacker to connect to it. Easily detected by security systems.
    - **Reverse Shell:** The victim’s machine initiates a connection to the attacker’s machine, bypassing inbound traffic filters and reducing visibility. Widely used due to lower detectability.
    - **Reuse-Socket:** Utilizes an existing connection between the attacker and victim to avoid triggering alerts from opening new ones. More complex as the shellcode must identify and reuse the correct connection.

### MetaSploit

**Metasploit:** Open-source platform designed for penetration testing and exploit development. It aids security professionals in identifying, developing, and testing exploits in a controlled manner to uncover vulnerabilities and weaknesses in networks and applications.

- **Two Ways to Interact with Metasploit:**
    - **MSFconsole:** Interactive command-line console offering full control over Metasploit's functionalities.
    - **Armitage:** GUI-based interface simplifying Metasploit interaction, ideal for users less familiar with command-line tools.

**Metasploit Modules**: Metasploit works through a series of specialized modules that perform different tasks during penetration testing. The most common modules are:

- **Exploits:** Take advantage of vulnerabilities in systems or applications to gain unauthorized access.
- **Payloads:** Instructions executed after a successful exploit. There are two types:
    - **Non-Staged (one-step):** Execute commands immediately on the victim to establish connections or create users. They are direct and self-contained.
    - **Staged (two-step):** First, establish a connection, and then load the full code, allowing for more complex actions and evading detection (if the buffer doesn’t allow the full payload, it's split into two steps).
- **Encoders:** Modify exploits and payloads to avoid detection by security tools like antivirus or IDS/IPS.
- **Auxiliary:** Support tasks such as vulnerability scanning or brute-force attacks.
- **Post:** Perform post-exploitation tasks such as maintaining persistent access, gathering information, or automating post-exploitation processes like transferring files.

**MSFvenom:** Metasploit tool used to generate shellcodes and payloads in multiple formats and platforms, streamlining the creation of exploits with standardized commands.

- **Shellcodes:** Creates specific shellcodes for systems like **Linux**, **Windows**, and **Mac**, tailored to execute instructions on each system.
- **Payloads:** Generates payloads to execute code on servers in languages like **PHP**, **ASP**, **JSP**, and **WAR**.
- **Scripts:** Supports creating **scripts** in **Python**, **Bash**, and **Perl** to be used across various platforms.

## **Privilege Escalation Phase**

**Privilege escalation**: The fourth phase of the audit, where the attacker seeks to obtain elevated permissions on a system after gaining initial limited access. This enables the attacker to execute actions and tools that require administrative privileges, fully compromising the system or network.

- **Common privilege escalation techniques:**
    - **Configuration flaws**: Default passwords or incorrect permission management.
    - **Weak authentication or authorization**: Exploiting authentication vulnerabilities to bypass restrictions or impersonate privileged users.
    - **Exploit execution**: Using known exploits to take advantage of vulnerabilities and gain elevated privileges.
    - **Process injection**: Injecting code into processes running with elevated privileges to perform actions with those privileges.
    - **Service modification**: Altering services running with elevated privileges to execute tasks with those privileges.
    - **Finding privileged user credentials**: Brute force attacks or credential collection through hacking techniques.
    - **Reusing hashes or tokens**: Capturing and reusing password hashes or session tokens to impersonate privileged users.

**Advanced Privilege Escalation Techniques:**

- **Privilege Escalation with Metasploit:**
    - **Meterpreter**: Advanced shell offering features like information gathering, file transfer, and command execution. The **Getsystem** module attempts to escalate privileges on vulnerable systems, automatically trying various techniques if no specific one is defined.
    - **Specific Exploits**: If **Getsystem** fails, specific exploits like **ms10_015_kitrap0d** can be used to take advantage of vulnerabilities and gain elevated privileges on Windows systems. This exploit, executed from Meterpreter, returns a new session with administrator privileges (nt authority\system).
- **Brute Force**: Automated brute force attack to discover privileged user credentials. To avoid detection, attack intensity can be adjusted, and a **password dictionary** can be used to speed up the process.
    - **Tools**: Medusa, Ncrack, Hydra, and Patator.
- **Credential Extraction**: **Mimikatz** is an open-source tool that extracts passwords, hashes, and Kerberos tickets from memory on a device. These credentials can be used to impersonate legitimate users and gain access.
- **Pass the Hash**: A technique that uses the password hash instead of the plaintext password for authentication. It exploits services that accept hashes for authentication, bypassing the time-consuming and resource-heavy password cracking process.
    - **Tools**: Metasploit, Mimikatz, pth-toolkit, FreeRDP, and Nmap.
- **Password Cracking**: A technique used to discover plaintext passwords from their hashes. Potential passwords are hashed from a wordlist until the resulting hash matches the target.
    - **Tools**: John the Ripper and Hashcat.
- **Pivoting**: A technique for moving laterally within a network, reaching systems that are otherwise inaccessible from the attacker's machine, using a compromised machine as an access point.
    - **Meterpreter** is an advanced payload from Metasploit that facilitates pivoting with network tunnels, port forwarding, and session chaining, allowing interaction with other machines within the compromised network.

---

## **Web Application Auditing**

**OWASP (Open Web Application Security Project)**: Global community focused on improving software security, particularly web applications. It provides educational resources, tools, and documentation to help developers and security professionals build more secure applications.

**OWASP Top 10**: List of the ten most common and critical vulnerabilities in web applications. It serves as a guide to identify and mitigate the most prevalent risks in application development.

**OWASP Testing Guide**: A guide for conducting security audits of web applications, focused on standardizing tests to ensure comprehensive evaluation. Its goal is to help identify vulnerabilities through testing across various areas of the application. Not all tests apply to every application; each test's relevance depends on the specific application being evaluated.

- **Types of Tests:**
    1. **Information Gathering**: Investigates the application's structure, web server, and components to identify potential weaknesses.
    2. **Configuration and Deployment Management**: Reviews server and component configurations to detect insecure setups.
    3. **Identity Management**: Evaluates user management, roles, and registration processes.
    4. **Authentication**: Ensures the authentication process is secure, that data is transmitted securely, and that passwords follow appropriate policies.
    5. **Authorization**: Verifies that users only access what they're authorized to and ensures there are no privilege escalation vulnerabilities.
    6. **Session Management**: Evaluates the security of session handling, cookies, and logout processes.
    7. **Input Handling**: Tests user input for injection vulnerabilities.
    8. **Error Handling**: Ensures errors do not expose sensitive information.
    9. **Weak Encryption**: Reviews encryption usage to ensure outdated methods are not used.
    10. **Business Logic**: Tests the internal logic of the application by manipulating processing times or sending unexpected requests to detect design flaws.
    11. **Client-Side Testing**: Evaluates vulnerabilities in the code executed in the browser, such as XSS and injection flaws.

**Web Audit Phases:**

1. **Planning Phase**: Aligning expectations with application owners. Defining dates, the type of audit (black, grey, or white-box), scope, objectives, and points of contact in case of critical vulnerabilities.
2. **Information Gathering Phase**:
    - **Footprinting**: Collecting public information without interacting with the target.
    - **Fingerprinting**: Gathering information by interacting with the application.
        - **Passive Method**: Intercepting and analyzing the traffic generated by the application.
        - **Active Method**: Sending requests or packets to the application to observe its responses.
3. **Execution Phase**: Performing tests on the application:
    - **Active Scanning**: Scanning the application and specific pages considered most vulnerable to identify weaknesses.
    - **OWASP Controls** and additional **tests** to detect vulnerabilities.
    - **Evidence Capture**: Collecting evidence of detected vulnerabilities to justify their existence in the final report.
4. **Reporting Phase**: Presenting clear and detailed results of the vulnerabilities found.

**Information Gathering Techniques for Web Audit:**

- **Search Engines**: Using Google Dorks and specialized search engines like Shodan to gather public data about the application and connected devices.
- **Whois**: Domain lookups to obtain details like owner, associated domains, and contact information.
- **Navigating the Application**: Inspecting the app for vulnerable pages such as forms or login.
- **Application Mapping**: Creating a schematic of pages using spiders or crawlers like Burp Suite.
- **Source Code**: Reviewing code for sensitive information, software versions, and relevant comments.
- **Metadata**: Analyzing files with tools like ExifTool, FOCA, or Metagoofil to gather additional information, such as employee names or software used.
- **HTTP Headers**: Reviewing headers to identify server products and versions.
- **Open Ports**: Scanning for open ports with Nmap.
- **"Robots.txt"**: File at the server’s root that contains paths that should not be indexed by search engines; reviewing it may reveal confidential sections.

**Techniques for Vulnerability Searching:**

- **CVE Details**: A web-based database that allows searching vulnerabilities by vendor, product, and version.
- **NIST Database**: The NIST database for checking product vulnerability details.

**Automated Scanners**: Tools that automatically detect vulnerabilities by performing security tests on a URL. They are useful but may generate false positives or negatives, so they should be used as a complement to manual audits.

- **Examples**: OWASP ZAP, Vega, Arachni, Burp Suite Professional, and Acunetix.

### Vulnerabilities

**Injection**: An attack that exploits unvalidated inputs to execute unauthorized commands or queries on the server.

- **SQL Injection (SQLi)**: Manipulates SQL queries by injecting malicious data into inputs.
    - **SQLi Blind**: The application only responds if the query is valid, showing a generic page on error.
    - **Detection**: Input characters like `'` or `"` to provoke errors or specific messages.
- **LDAP Injection**: Manipulates LDAP queries used in authentication by injecting characters like `*` (wildcard in LDAP).
    - In the `Name:` field of the form, input `Pablo` → query `(username=Pablo)`
    - In the `Name:` field of the form, input `Pablo)(password=*` → query `(username=Pablo)(password=*)`
    - **Detection**: Test LDAP characters, such as multiple `)`, looking for errors like the 500 error specific to LDAP.
- **Code Injection**: Injects code in the programming language used by the application (PHP, ASP…).
    - **Detection**: Test with basic commands in the language.
- **Command Injection**: Executes OS commands via the application. The commands are entered through a shell and, if successful, are executed with the application's privileges.
    - **Detection**: Test with basic commands such as `/bin/ls`.
- **Other Types**: Injection in XPath, XML, HTML, CSS, adapted to the input context.

**Cross-Site Scripting (XSS)**: Exploits the lack of input validation to execute malicious scripts, such as unverified JavaScript, which allows:

- **Session Hijacking**: Capturing cookies to impersonate a user.
- **Information Theft**: Retrieving sensitive data, such as browsing history.
- **Defacement**: Altering the visible content of a webpage.
- **Malware Installation**: Inserting malicious software, such as backdoors.
- **Types of XSS:**
    - **Reflected XSS**: The attacker creates a legitimate URL to a legitimate site (e.g., Facebook) but includes a malicious script in the parameters. When the victim clicks this URL, the server processes the script and reflects it in the response, causing the victim's browser to execute it when the page loads.
        - The script only executes when the specific link created by the attacker is used. If the victim accesses the page another way, it works normally.
    - **DOM-based XSS**: The malicious script is included in a URL and dynamically alters the DOM (Document Object Model) in the victim's browser.
        - The vulnerability occurs only in the affected browser. If the page is accessed in any other way, no malicious code runs.
    - **Stored/Persistent XSS**: The malicious script is inserted into the application's database, so that every time a user accesses the compromised page, the browser automatically executes the code.
        - Forums or pages with comment sections are common vulnerable targets.
- **Detection**: Test with special characters (`<`, `>`, `"`), or basic payloads like `<script>alert('test')</script>`. If the browser executes the script, the page is vulnerable.

**File inclusion**: Occurs when a web application allows an attacker to control which file is included and executed on the server, and the type and content of the file are not properly verified.

- **Remote File Inclusion (RFI)**: The application loads and executes a remote file provided by the attacker, usually through a parameter in HTTP or FTP.
- **Local File Inclusion (LFI)**: The application includes local files from the server. While remote files are not downloaded, an attacker can exploit this vulnerability to access sensitive files (like system logs) or even execute malicious code stored on the server.
- **Detection**: Test if the application allows dynamic manipulation of file paths through URL parameters or other inputs. Attempt to include files to verify if the application properly validates paths and restricts access to sensitive resources.

**Cross-Site Request Forgery (CSRF)**: 

- `A` is a legitimate web application where the victim is authenticated.
- `B` is an application controlled by the attacker.
- The attack involves tricking the victim into accessing `B` (for example, via social engineering), from where a request is sent to `A` on behalf of the victim. Since `A` trusts the victim due to their authentication, unauthorized commands are executed without their knowledge.
- **Detection**: Use tools like **CSRFTester** from OWASP or the **Generate CSRF POC** feature in BurpSuite to create PoCs and verify the presence of the vulnerability.

---

## Mobile Application Auditing

**OWASP Mobile Security Testing Guide**: A guide to assess security risks in mobile applications, focusing on protecting data stored on the device or transmitted to the server, and proposing mitigation measures.

**Tests performed:**

- **Architecture, Design, and Threat Model**: Review the components (code, libraries, APIs) and the application's structure to identify security risks from the start. This includes:
    - Architecture analysis (servers, databases)
    - Implementation of security controls
    - Defining a threat model to understand how an attacker could exploit vulnerabilities
- **Data Storage and Privacy**: Ensure that sensitive data (credentials, cryptographic keys, private information) is managed securely. Verifies that:
    - Data is properly stored
    - Sensitive information is not leaked (in logs or screenshots)
    - Data is protected both at rest and in transit
- **Cryptography**: Ensure the application uses strong cryptography according to industry best practices. Verifies that:
    - Insecure, outdated algorithms or hardcoded keys are not used
    - Validated cryptographic primitives are employed
    - Algorithms use proper parameters, such as correct key sizes and securely generated random values
- **Authentication and Session Management**: Assess the security of user account and session management. Verifies that:
    - Secure authentication methods are used
    - Access tokens are generated randomly to avoid constant credential transmission
    - Sessions expire after a period of inactivity
    - Logout properly removes all session traces
    - A strong password policy and temporary account lockout after failed attempts are implemented
    - Biometric authentication is securely implemented using a keychain/keystore system
- **Communications**: Ensure that information between the app and remote services is confidential and intact. Verifies that:
    - TLS encryption is used to protect data in transit
    - Server certificates are correctly validated
- **Platform Interaction**: Ensure the secure use of platform APIs and standard components. This includes:
    - Proper input validation
    - Denial of JavaScript use, unless strictly necessary
    - Exclusive use of HTTPS in WebViews
- **Code Quality**: Verify that the application follows secure coding best practices. Checks include:
    - The application is signed with a valid certificate
    - Debug symbols and code are removed from binaries
    - Exceptions are properly handled
- **Resilience**: Ensure the application is resilient to attacks. Verifies that:
    - Detection of rooted devices or jailbroken phones, with measures such as altering the flow or terminating the app
    - Use of reverse engineering tools, code injection, hooking frameworks, or debugging servers is identified

**2 Types of Mobile Application Analysis:**

- **Static Analysis**: The source code, components, and structure of the application are analyzed without executing it. This focuses on identifying vulnerabilities related to the code's behavior and potential attacks from input data.
- **Dynamic Analysis**: This analysis occurs while the application is running, observing interactions with device components (memory and file access), communications, and data channel security.

### **Mobile Application Analysis on Android**

**Static Analysis:**

1. **Obtain the APK file:**
    - **APK Extractor**: App that extracts the APK from installed applications on the mobile device.
    - **ADB (Android Debug Bridge)**: Allows access to the Android device via USB to obtain the APK.
    - **Download from third parties**: Websites like APK Downloader allow downloading the APK from Google Play by providing the app’s URL.
2. **Decompress the APK file**: After obtaining the APK, it must be decompressed to access its files.
    - **APKTool**: A Java tool to decompress the APK and get SMALI code. `java -jar apktool_2.3.2.jar d <apk_name>` extracts the files, and `java -jar apktool_2.3.2.jar b <code_directory> <apk_name>` recompiles the decompressed code.
3. **Converting APK Code**: After decompressing the APK, the source code is in .dex (Dalvik Executable) files, similar to assembly language.
    - **Convert DEX to JAR**: Using the **Dex2jar** tool: `sh d2jar-dex2jar.sh -f <app_name.apk>`.
    - **Decompile the JAR**: The **JD-GUI** tool displays the decompiled Java code: `java -jar jd-gui-1.4.0.jar`. It provides a graphical interface for analyzing the code. **Grep** is an alternative without a graphical interface.
4. **File and Data Analysis:**
    - **AndroidManifest.xml**: Contains the app configuration, including permissions and internal components.
        - **Permissions**: Check if the requested permissions (camera, GPS, etc.) are necessary.
        - **Key checks**:
            - `android:allowBackup="false"` → Prevent unwanted backups.
            - `android:debuggable="true"` → Ensure the app isn't in debug mode.
            - `intent-filters` have `android:exported="false"` → Prevent undesired interactions with other apps.
    - **Application Digital Certificate (RSA)**: The app must be signed with a digital certificate (.rsa or .dsa) to verify its authenticity and link it to an owner.
        - **Certificate Verification**: Use **Keytool** to obtain information about the certificate: `Keytool –printcert –file META-INF/CERT.RSA`.
        - **Review Additional Certificates**: Verify SSL/TLS certificates for secure communications and server certificate validation to prevent spoofing.
    - **App Resources**: Identify resources that might store sensitive data.
        - **Local Databases**: Look for .db files using **SQLite Browser**.
        - **Shared Preferences Files**: XML files that may contain sensitive data, located at `/data/data/<package_name>/shared_prefs`.
        - **Use ADB Shell**: To review data stored on the device (cache and installation directories) and check file access permissions.
5. **Source Code Analysis:**
    - **Plaintext Credentials**: Check for credentials like username/password, API keys, or tokens in the source code, strings, URLs, or SQL statements. If they are in comments, they may not be retrieved upon decompiling the app.
    - **Exposed URLs or IPs**: Search for IP addresses or URLs indicating the servers or resources the app connects to.
    - **Unvalidated Log Outputs**: Analyze logs that might contain sensitive information without validation, such as `Log.i()` or `System.out.print()`.
    - **Use of Weak Encryption Algorithms**: Check for the use of insecure algorithms like DES, MD5, or SHA-1 for sensitive data.
    - **Permissions in Code**: Verify if the app directly invokes permissions in the code, such as storage access via `Context`.
    - **Temporary Files**: Analyze if the app creates temporary files on devices with write permissions, like `createTempFile()`, which could expose data.
    - **Insecure WebView**: Check if the app uses WebView correctly to avoid vulnerabilities like MITM or XSS.
    - **SQL Injection**: Search for SQL queries that concatenate user-supplied parameters, such as in `rawQuery()` or `execSQL()`.
    - **Execution of System Commands**: Review if the app executes system commands with user input, which could allow malicious code execution. Example: `getRuntime().exec("ls -la")`.
    - **Rooted Device Detection**: Verify if the app checks if the device is rooted using methods like `RootTools.isAccessGiven()`.
    - **Certificate Validation**: Ensure that the app verifies the hostname of certificates to prevent MITM attacks. Example: `HttpsURLConnection.setDefaultHostnameVerifier(NullHostnameVerifier)`.
    - **Insecure Random Number Generation**: Check for methods like `Math.random()` used to generate OTP codes or passwords.
    - **Device Data Access**: Review unauthorized access to sensitive device information, such as SIM number or location. Look for classes like `TelephonyManager` and methods like `getDeviceId()`.
    - **Sending SMS Without Consent**: Analyze the use of permissions and methods like `SmsManager.sendTextMessage()` to prevent abuses like mass SMS sending.
    - **Location Enabled**: Verify access to the device's location without user consent, using methods like `getLatitude()` and `getLongitude()`.
    - **Hidden Fields**: Check for sensitive information hidden in the UI using attributes like `android:visibility=invisible`, as they may conceal buttons or data submitted with user credentials.
6. **Automated Security Analysis Tools:**
    - **MobSF**: Tool that performs both static and dynamic analysis, decompiles the APK, and generates a report with vulnerabilities. It only requires cloning the repository, installing dependencies, and uploading the APK.
    - **SUPER Android Analyzer**: A fast analysis tool that decompiles the APK and generates an HTML report with vulnerable code snippets, without needing external dependencies.

**Dynamic Analysis**:

- **Configure Device/Emulator** to intercept traffic and review actions:
    - **Intercept HTTPS Traffic on Android versions prior to 7.0**:
        1. Obtain the IP address and port of the Burp host.
        2. Connect the device to the same Wi-Fi network as the Burp host and set up the proxy with the IP and port.
        3. Download the certificate from Burp's URL, change the extension to .cer, and install it on the device.
    - **Intercept HTTPS Traffic on Android 7.0+:**
        - Android 7.0+ prevents apps from using user-installed certificates by default.
        1. Decompile the app using tools like APKTool.
        2. Modify the "AndroidManifest.xml" to specify the path to the certificate. The `android:networkSecurityConfig` attribute allows the use of user certificates.
        3. Recompile the app with tools like APKTool.
    - **Use ADB**: Obtain real-time logs using Logcat to review interactions, debug messages, and user actions.
- **Review Application Interaction in Two Phases**:
    - **Internal Interaction**: Analyze the data stored on the device, such as credentials, configuration files, user profiles, and temporary files.
    - **Interaction with Web Servers**: Observe how the app communicates with external servers, analyzing the data sent and the responses received.
- **Evasion of Main Security Countermeasures**:
    - **Certificate Pinning**: Ensures communication only with legitimate servers by verifying the server's certificate against the one hardcoded in the app.
        - **Bypass**: Modify the code at runtime using **Frida** to intercept traffic and inject JavaScript to alter certificate validation.
    - **Rooted Device Detection**: Identifies if a device is rooted, which could allow malicious apps to access sensitive data or intercept communications.
        - **Bypass**: Use **Frida** to inject code to manipulate root checks, or use **RootCloak** to hide the rooted state.

### Mobile Application Analysis on iOS

**Static Analysis**:

- **Frameworks for Automated Static Analysis**: Tools like **MobSF**, **Passionfruit**, and **Brida** extract key information from IPA files, including configurations, classes, libraries, and potential vulnerabilities, facilitating auditing without the need for exhaustive manual analysis.
1. **Obtain the IPA file (iOS App Store Package)**: This is the installation package for an iOS application, similar to the APK file for Android, and contains both the compiled code and static resources (images, sounds…).
    - Previously obtained via iTunes or the App Store,
    - Today, it can be acquired using tools like **Apple Configurator** or through direct downloads from development sources like **Xcode** or testing tools like **TestFlight**.
    - **IPA File Directory Structure**:
        - `/Payload/`: The main folder containing the **.app** file, which holds the compiled ARM code and static resources (images, sounds...).
        - `/iTunesArtwork/`: Contains the application image that appears in iTunes.
        - `/iTunesMetadata.plist/`: A file with information such as the developer identifier, bundle ID, copyright, release date...
2. **Access App Files on an iOS Device via SSH**:
    - **Search Command**: Use `find` to locate the app by name.
    - **Storage Path**: Apps are located in `/var/mobile/Containers/` with a unique UUID.
    - **Directory Structure**: The app is broken down into several folders:
        - `/Application.app`: Contains the app's code and resources.
        - `/Documents`: Files created by the app.
        - `/Library`: Configuration and preference data.
        - `/tmp`: Temporary files.
3. **Analyze Information Stored on the Local Device**:
    - **Configuration Files (.plist)**: Contain app configurations and properties. These can be read and modified with `plutil -p` to convert them to a readable format.
    - **Databases (.sqlite, .dat, .db)**: May store sensitive information. They can be located with the `find . -name *.db` command.
    - **Keychain**: Stores sensitive data such as tokens, passwords, or encryption keys. Accessed via specific APIs, and the database is located at `/private/var/Keychains/keychain-2.db`. It's crucial to verify that the data is protected by appropriate Data Protection classes.
    - **Session Cookies**: Stored in `Cookies.binarycookies` and can be extracted and analyzed with Python scripts or tools like Needle.
4. **Decrypting the Binary**: App Store apps are encrypted. To analyze them, it's necessary to decrypt the executable with tools like **Clutch** or **Dumpdecrypted**, which are run on a jailbroken device.
    - **Extracting Information**: After decryption, details about the app's architecture, symbols, and text strings can be extracted using tools like **Rabin2**.
    - **Class Extraction**: Tools like **Class Dump** or **Clutch** allow the extraction of classes and methods from the binary, providing a more detailed representation of the code, which helps in analyzing its structure.

**Dynamic Analysis**:

1. **Installing the Certificate for Traffic Analysis with Burp Suite**:
Start Burp Proxy on your computer, access `http://<Computer_IP>:<Port>` from the mobile device, download and install the Burp root CA certificate.
2. **Obstacles for Dynamic Analysis**:
    - **SSL Pinning** and **End-to-End (E2E) Encryption** block traffic interception.
        - To disable **SSL Pinning**, use **SSL Kill Switch 2** to disable SSL certificate verification at a low level.
    - **Jailbreak Detection** restricts app execution on jailbroken devices, limiting the use of tools.
        - **Frida** allows injecting code into apps to bypass jailbreak detection. Use the command `frida-trace -U -f ...` to intercept the function checking for jailbreak and change the return value to "no-jailbreak," allowing the app to run normally.
    

---

## Audit Report

**Audit Report:** A document presenting a detailed analysis of the security of a system or application, highlighting vulnerabilities, their impact, and improvement recommendations, tailored to technical and executive audiences as appropriate.

1. **Introduction:** A brief overview of the purpose and scope of the audit, including:
    - Type of test performed (white-box, gray-box, or black-box) and user profiles audited, if applicable.
    - Restrictions or limitations that affected the audit, such as difficulties encountered during testing.
    - Criteria used to classify the severity of identified issues.
2. **Methodology:** A description of the approach followed during the audit, typically including:
    - Explanation of the security framework used (such as OWASP, NIST, etc.) and its adaptation to the audit.
    - Description of the areas analyzed (access control, session management, configurations, etc.).
    - **Process Stages:** From initial information gathering to the identification and validation of vulnerabilities.
3. **Executive Report:** A summary accessible to non-technical leaders within the organization, aimed at facilitating strategic decisions on security. It includes:
    - **Application Security Status:** General security level based on findings.
    - **Detected Vulnerabilities:** A visual summary with a graph showing the number and severity of vulnerabilities (low, medium, high, critical).
    - **Key Risks:** Description of the most significant risks arising from critical vulnerabilities, with focus on their potential impact.
    - **Summary Table:** Details of vulnerabilities, their risk, and current status (fixed or open), crucial for follow-up audits. General recommendations without delving into technical details.
4. **Technical Report**: A detailed document for developers and application owners, enabling corrective actions. It includes:
    - **Unique Identifier** of the vulnerability.
    - **Severity** of the vulnerability, with CVSS score or specific impact.
    - **Affected Machine/URL/Service**, including IP, network range, or URL.
    - **Vulnerable Fields** if they apply to specific areas of the application.
    - **Brief Description** of the vulnerability.
    - **Associated Risks** if the vulnerability is not fixed.
    - **Detection Details**: Explanation of the identification process and examples (e.g., HTTP requests).
    - **Visual Evidence**: Clear images showing the vulnerability.
    - **Additional References** to help understand and resolve the vulnerability.
    
    The content and structure of reports are flexible, so the results can be presented with information organized in tables to enhance visualization and action.
    

![image.png](https://github.com/Pablo-NR/Cybersecurity-Master/blob/main/Images/image1.png)