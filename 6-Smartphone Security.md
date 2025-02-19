# 6. Smartphone Security

## Introduction

**5 Conceptual Pillars of Security:**

- **Prevention:** Proactive measures to reduce the likelihood of threats.
    - Installation and updating of security tools.
    - Implementation of policies and usage/configuration guidelines.
    - Identification and control of attack vectors (hardware, software, configurations, human factors).
- **Detection:** Early identification of threats, assuming prevention is not sufficient.
    - Use of antivirus software, traffic analyzers.
    - Reviews in official marketplaces, user reports, and complaints.
    - Detection of attacks before causing significant damage.
- **Mitigation:** Techniques to reduce the impact of a detected threat while it is being eliminated.
    - System isolation to prevent propagation.
    - Data restoration from backups.
    - Changing compromised credentials.
- **Elimination:** Complete eradication of the threat.
    - Malware removal using antivirus software.
    - Shutdown of services or uninstallation of vulnerable software.
    - Use of sandboxing in mobile devices to isolate malicious processes.
- **Anticipation:** Preparation for future threats.
    - Ongoing research by security laboratories and antivirus companies.
    - Early identification of new vulnerabilities and attacks.

**5 Fundamental Tasks of Security Managers:**

- **Planning and coordination:** Designing and managing the deployment of security mechanisms, focusing on prevention and detection.
- **Verification and efficiency:** Ensuring the proper functioning and availability of implemented mechanisms.
- **Time optimization:** Reducing response times and implementing measures to minimize damage.
- **Risk analysis:** Evaluating strategies and operations, identifying vulnerabilities and new needs.
- **Strategic contribution:** Establishing priorities and making decisions based on continuous analysis

**Profile and Classification of Attackers:**

- **Motivation:**
    - **Curiosity:** Attack for experimentation, without clear criminal intent.
    - **Personal fame:** Seek notoriety by exposing compromised data as trophies.
    - **Tangible personal benefit:** Gain profits through deception, such as malicious apps.
    - **Revenge/retaliation:** Attack out of resentment, damaging the reputation of specific targets.
- **Target Sectors:**
    - **Personal:** Attacks on individuals, such as credential theft or unauthorized access to private information.
    - **Institutional:** Massive or targeted attacks on organizations with higher potential benefits.
- **Ecosystem:**
    - **Android:** The predominant system, with the highest malware incidence (>95%) due to the ease of publishing apps, poor verification, and fragmentation (devices with outdated and unpatched versions).
    - **iOS:** Fewer attacks due to strict identity controls, higher security, and widespread use in corporate environments.

**Passcodes:** Locking mechanisms in mobile devices that protect information in case of loss or theft.

- **Expiration and reuse:** Passcodes can expire and require periodic changes. It is recommended to prevent reuse of previous passcodes.
- **Maximum attempts:** Limits the number of attempts to prevent brute force attacks; exceeding the limit results in device lockout or data wipe.
- **Types:**
    - **PIN:** A numeric code also used for SIM cards and payments. Vulnerable to brute force attacks due to its limited range.
    - **Password:** Alphanumeric with special characters, more secure than a PIN if it is strong.
    - **Pattern lock:** A drawn pattern on a 3×3 grid encoded based on the order of connected points, more secure with 7-9 point combinations.
- **Attacks:**
    - **Smudge attack:** Analyzing screen marks to reveal the passcode.
    - **Bug exploitation:** Some bugs allow bypassing authentication to access data.
    - **Brute force or dictionary attacks.**
- **Biometric alternative:** Uses unique traits for authentication (fingerprint, face, iris, voice).
    - Data is stored in secure zones (Secure Enclave [Apple], TEE [Android]).
    - Cannot be shared or reversed to its original form.

**Locking / Wiping:** Mechanisms that protect mobile device data in case of loss or theft, preventing unauthorized access.

- **Remote locking / wiping:** iOS and Android allow remote locking or data wiping to protect information. However, it may be insufficient if the attacker accesses the data before activation.
- **Local locking / wiping:** Policies that, after several failed passcode attempts, progressively lock or wipe the device.
- **Additional considerations:**
    - Brute force attacks are hindered by limiting attempts and increasing wait times.
    - Remote wiping restores the device to factory settings, requiring backups to recover data.

**App Stores:** Official download platforms that verify developer identities and ensure app integrity and security.

- **Application digital signatures:**
    - **Apple App Store:** Requires digital certificates issued by Apple to validate developer identity and app integrity.
        - **Closed store:** Apple reviews each app before publication, assessing security, usability, and performance.
    - **Google Play:** Requires digital signatures but allows self-signed certificates, implying less control.
        - **Open store:** Google Play allows more flexible publishing, relying on digital signatures, which facilitates the presence of malicious apps.
        - **Google Play Protect (Bouncer):** A software scanner that analyzes apps, updates, and developer accounts for malware and suspicious behavior by running them in a simulated environment.

**Encryption and Security Protocols:** Methods and protocols that protect stored and transmitted information on mobile devices, ensuring confidentiality, integrity, and authenticity in communications. Their effectiveness depends on proper implementation and the use of tested libraries.

- **Cryptographic libraries:**
    - **Apple:** Common Crypto is Apple’s native library, controlling implementations, protocols, and algorithms on its platform.
    - **Android:** Uses multiple libraries, including Android OpenSSL, Bouncy Castle, and Crypto.
- **Internal data encryption:** Protects the entire device memory in case of loss or theft.
    - Keys are stored in hardware-protected areas (Secure Enclave [iOS], TEE [Android]), and backups can be encrypted.
    - **iOS:** Uses AES with 256-bit keys.
    - **Android:** Uses AES with 128-bit keys.
- **SSL/TLS:** Protocols that establish secure channels over TCP connections (HTTP, FTP, IMAP, etc.) by negotiating encryption algorithms and securely exchanging session keys.
    - Ensure integrity through a message authentication code (MAC) in each data fragment.
    - Security depends on proper validation of certificates issued by trusted Certificate Authorities (CAs).
    - **SSL/TLS Attacks:**
        - **MITM (Man-in-the-Middle):** Intercepts, modifies, or redirects traffic between client and server.
        - **POODLE:** Exploits SSL 3.0 and some outdated TLS versions to force connection downgrade and decrypt communications.
    - **SSL/TLS Countermeasures:**
        - **Secure configurations and updates:** For example, Google Play ensures that the Security Provider is updated on Android.
        - **Analysis tools:** Nogotofail detects SSL/TLS vulnerabilities.
        - **Pinning:** Hardcodes public key hashes of valid certificates to prevent the use of fraudulent certificates; can be implemented dynamically for more flexibility.
        - **HSTS (HTTP Strict Transport Security):** Enforces HTTPS connections, instructing the client via the corresponding HTTP header.
- **VPN (Virtual Private Network):** An encrypted tunnel that connects private networks over the Internet, allowing devices and remote networks to be part of a secure network.
    - Used to connect corporate branches and bypass regional restrictions.
    - Secure protocols like **IPsec** and **OpenVPN** authenticate client and server using credentials or certificates.
    - Obsolete protocols like **PPTP** are insecure due to vulnerabilities in their encryption.

---

## Wireless Network Security

**Wifi:** Technology based on the IEEE 802.11 standard that enables wireless connections to local networks and the Internet. The "Wi-Fi" certification is granted by the Wi-Fi Alliance, ensuring compatibility between devices that comply with the standard.

- **Operating modes:**
    - **Ad hoc Wi-Fi:** A decentralized network where devices communicate directly without an access point.
        - Requires prior agreement on channel, name, security, and key.
        - Mainly used for direct PC-to-PC connections, not common in home or business networks.
    - **Infrastructure mode:** The standard setup for home and business networks, allowing the use of Wi-Fi security mechanisms.
        - A router or AP centralizes the network, manages traffic, and defines parameters such as speed and security.
- **Wi-Fi network identifiers:**
    - **MAC address:** Each device has a unique address inherited from Ethernet.
    - **BSSID:** Unique network identifier in infrastructure mode, usually the MAC address of the router or AP.
    - **ESSID:** Network name (up to 32 characters) used to identify it in environments with multiple networks.
- **Management frames:**
    - **Beacon frames:** Periodically broadcast packets announcing the network and its characteristics (MAC, ESSID, capabilities, etc.). Their constant emission can aid malicious actors in detecting networks.
    - **Probe requests:** Sent by devices searching for known networks to connect automatically.
- **Wi-Fi network scanners:** Software that analyzes the wireless spectrum, identifying networks, connected clients, and MAC addresses.
    - Used in security audits and attacks to detect vulnerable networks.
    - **Examples:** **Windows:** NetStumbler | **GNU/Linux:** Kismet, Airodump-ng (Aircrack-ng).

**Ineffective Security Mechanisms:** Strategies that do not effectively prevent data theft or unauthorized access.

- **Network hiding:** Disabling ESSID broadcast in beacon frames to "hide" the network name, but:
    - Devices still send probe requests that reveal the ESSID, and tools like Kismet can detect these responses, exposing the network.
    - Probe requests can reveal a history of known networks, aiding attackers in identifying past connections.
- **MAC address filtering:** Uses whitelists or blacklists to allow or deny access based on MAC addresses, but:
    - MAC addresses can be easily spoofed with software like **Macchanger** on GNU/Linux.
    - In blacklists, changing the MAC address bypasses the block; in whitelists, attackers can clone authorized addresses.
    - This method does not prevent passive traffic interception and should be combined with robust encryption.

**WEP (Wired Equivalent Privacy):** An encryption mechanism for IEEE 802.11 networks intended to provide confidentiality similar to wired networks but with critical vulnerabilities, making it only a deterrent for non-technical users.

- **Functionality:**
    - **Shared secret key:** A 5- or 13-character key is used between the AP and clients to generate unique per-packet keys.
    - **Initialization Vector (IV):** A 3-byte pseudo-random prefix generated for each packet and concatenated with the key (e.g., "123" + "abcde" = "123abcde"), transmitted in plaintext.
    - **RC4 encryption algorithm:**
        - **KSA (Key Scheduling Algorithm):** Initializes a pseudo-random matrix based on the IV + key.
        - **PRGA (Pseudo-Random Generation Algorithm):** Generates a bit stream combined with plaintext using **XOR operation**, allowing reversibility if one of the elements is known.
- **Weaknesses:**
    - **IV transmission in plaintext:** Allows easy capture and analysis, enabling key deduction.
    - **Patterns in KSA and PRGA:** Early iterations exhibit predictable patterns, facilitating key byte recovery.
    - **Known headers:** The fixed SNAP header (0xAA) allows attackers to obtain the first encryption stream byte using XOR.
- **Specific Attacks:**
    - **ARP Replay Attack:** Captures and replays valid ARP packets to force the router to emit new packets with vulnerable IVs, accelerating data collection.
    - **ChopChop Attack:** Exploits router responses to malformed packets to reconstruct the full encryption stream, allowing decryption without knowing the secret key.

**WPA1 (Wi-Fi Protected Access 1):** A protocol designed to overcome WEP's limitations by improving key construction and using **TKIP**, though it still inherits RC4 vulnerabilities that can be exploited.

- **Improvements over WEP:**
    - Uses **PSK (Pre-Shared Key)** with 8- to 63-character passwords, increasing complexity compared to WEP.
    - Includes an **Enterprise version (WPA-Enterprise)** that integrates authentication systems (RADIUS or 802.1X) for enhanced security.
- **Introduction of TKIP (Temporal Key Integrity Protocol):**
    - Generates unique **temporal keys** per packet, preventing IV reuse.
    - Combines **128-bit keys** with the **client’s MAC address** to strengthen link-layer security.
    - Uses hashing and sequential control to prevent weak IV exploitation.
- **Use of RC4 and dynamic keys:**
    - Although RC4 is still used, WPA1 changes temporary keys every **10,000 packets**, making data collection for attacks more difficult.
    - With sufficient traffic, a skilled attacker can still break the encryption, proving that WPA1, while more secure than WEP, remains vulnerable to advanced attacks.

**WPA2:** A Wi-Fi security protocol that overcomes WPA’s weaknesses by eliminating RC4 and adopting modern mechanisms (such as AES-128) to ensure **confidentiality, integrity, and authenticity** in communications.

- **Variants:**
    - **WPA2-Personal (PSK):** Uses a pre-shared key (8 to 63 characters) to authenticate all devices through a **4-way handshake**.
    - **WPA2-Enterprise:** Each device authenticates individually (username and password) using systems like **RADIUS or 802.1X**. The authentication server generates and renews keys randomly, preventing dictionary attacks.
- **Improvements over WPA1:**
    - **RC4 removal:** Replaces RC4 with **128-bit AES encryption**, eliminating vulnerabilities based on statistical analysis.
    - **Integrity control:** Replaces the **Michael algorithm** with **CBC-MAC (Cipher Block Chaining Message Authentication Code)**.
    - **No backward compatibility with old hardware:** Enables more advanced security techniques.
- **Encryption and authentication security:**
    - **AES encryption:** To date, no effective method has been found to break AES, making it the most robust encryption for wireless networks.
    - **4-Way Handshake:** Authenticates communication between the device and the AP.
        - In **WPA2-PSK**, although the handshake does not reveal the password directly, it provides a "copy of the lock" on which an attacker could attempt brute force on weak passwords.
- **Additional considerations:**
    - **Strong password:** Essential to mitigate dictionary attacks, especially with tools that accelerate brute force using GPUs.
    - **WPA2-Enterprise advantage:** Individual authentication and dynamic key management significantly reduce vulnerability to attacks based on handshake capture.

**3G/4G/5G Networks:** Mobile technologies for **voice and data**, each with specific security features and challenges.

- **Differences between generations:**
    - **3G:**
        - Core network based on **IP and SS7 protocol**, improving security in the backbone network.
        - Uses **KASUMI encryption** for **confidentiality (UEA1)** and **integrity (UIA1)** with 64-bit blocks and 128-bit keys, though it has accumulated weaknesses.
    - **4G:**
        - **Stronger security at the link layer**, but the all-IP core makes it more vulnerable if not properly managed.
        - Introduces new cryptographic algorithms:
            - **Confidentiality:** Initially **128-AEE2 (AES-CTR)**, evolving to **128-AEE3 (ZUC stream cipher)**.
            - **Integrity:** From **128-EIA2 (AES-CMAC)** to **128-EIA3**, providing greater robustness.
- **Algorithms and additional enhancements:**
    - **SNOW 3G:** A synchronous stream cipher based on **32-bit words**, using a **128-bit key and initialization vector**.
    - **Authentication:** Uses **mutual authentication and digital certificates**, reinforcing protection between base stations, devices, and core nodes.
- **Vulnerabilities and attacks:**
    - **Forced protocol downgrade:** Attackers can force a **fallback to 2G (GSM/EDGE)**, which uses **one-way authentication** and transmits data unencrypted (e.g., A5/0), facilitating **MITM attacks** via fake base stations.
    - **Mitigation measures:**
        - Configure devices to **reject GSM/EDGE**.
        - Use **end-to-end encryption** at the transport layer (**HTTPS, IPsec, SSH**).
        - Deploy **firewalls** on mobile devices.
- **Overall security improvements:**
    - **Mutual authentication:** All network nodes must authenticate each other.
    - **Comprehensive protection:** Encryption at both the **link layer and core network**, with stronger algorithms and longer keys.
    - **Use of digital certificates:** To authenticate base stations and other critical nodes.
    - **Integrity control:** Periodic security reviews of devices and network nodes.

**Bluetooth:** A short-range wireless technology (up to 100 meters) used for low-speed data exchange between mobile devices.

- **Main Versions:**
    - **Bluetooth Classic:** For high-power operations (e.g., streaming, communication between smartphones and tablets).
    - **Bluetooth Low Energy (LE):** Designed for resource-limited devices; iOS uses only this version, while Android supports both.
- **Key Functions:**
    - Environment scanning for device detection.
    - Management and query of paired devices.
    - Establishment of communication channels (mainly via RFCOMM).
    - Handling multiple simultaneous connections.
- **Architecture:** Based on a protocol stack organized in layers:
    - **LMP (Link Manager Protocol):** Controls the Bluetooth link, managing authentication, encryption, quality of service, connection establishment, and release.
    - **LELL (Low Energy Link Layer):** A simplified version of LMP for Bluetooth LE, optimized for low power consumption.
    - **L2CAP (Logical Link Control and Adaptation Protocol):** An adaptation layer operating above LMP/LELL, allowing multiple types of data to be sent over the same link, managing fragmentation, reassembly, and quality of service.
    - **SDP (Service Discovery Protocol):** Facilitates the discovery of available Bluetooth services on other devices.
    - **RFCOMM (Radio Frequency Communication):** Emulates **RS-232** serial port connections over L2CAP. Allows up to 60 simultaneous connections, used in peripherals and file transfers.
- **Security:** Managed by the **Security Manager**, located between LMP and L2CAP. It is responsible for pairing, authentication, encryption, and cryptographic key management.
    - **Security Modes:** Determine when and how security measures are applied.
        - **Mode 1 (Unsecure):** No authentication or encryption, allowing unrestricted connections. Used in open-access devices where security is not a priority.
        - **Mode 2 (Service-level security):** Security is applied based on the accessed service, allowing unencrypted connections while protecting sensitive data.
            - **Used in devices with multiple services**, where some may be public and others require protection.
            - Uses **Secure Simple Pairing (SSP)** during the initial pairing to exchange keys.
            - **Devices can be:**
                - **Trusted:** Authenticated and with a link key.
                - **Untrusted:** Without prior authentication.
            - **Protection levels:**
                - **Level 1:** No security.
                - **Level 2:** Requires authentication only.
                - **Level 3:** Requires authentication and authorization (by default, Level 3 for incoming devices and Level 2 for outgoing ones).
        - **Mode 3 (Link-level security):** Applies security before establishing the connection, protecting all communication from the start.
            - Used in devices handling sensitive data that require full protection.
            - Implemented via hardware and software (within the Bluetooth chip).
            - Encrypts all data, provides authentication (PIN up to 16 characters), and protects the MAC address.
            - **Secure Simple Pairing (SSP)** is also applied in this mode.
            - If a master key is used in multi-device networks, it must be securely distributed.
- **Security Algorithms:**
    - **Encryption:** **E0** stream cipher with keys up to 128 bits (typically 64 bits), protecting Bluetooth communication.
    - **Key Generation:** **E21 and E22** algorithms (based on SAFER+) derive session keys from shared initial keys.
    - **Authentication:** **E1** algorithm uses Message Authentication Codes (MAC) to verify device identity.
    - **Bluetooth 4.2:** Introduces **LE Secure Connections** with **ECDH (Elliptic Curve Diffie-Hellman),** a more robust key exchange system, particularly useful in low-power devices.
- **Key Generation:** Various link keys and an encryption key derived from them (except for the initialization key) are used:
    - **Initialization Key:** Temporarily used during pairing to protect parameter exchange and share the final link key. Discarded once the definitive key is established.
        - Based on a pre-shared PIN, a random number (16 bytes), and the device address (6 bytes).
    - **Combination Key:** Dynamically generated for each device pair during pairing. Used to encrypt communication between them.
    - **Unit Key:** Created during device installation and unique to each device. Used in authentication and pairing when no combination key is available.
    - **Master Key:** Used when a device acts as a master and needs to communicate simultaneously with multiple slaves in a Bluetooth network.
- **Authentication:** Based on a **challenge-response** scheme, where one device verifies the identity of the other before establishing a secure connection.
    - The verifier sends a challenge (128-bit random value).
    - The other device generates a response using the **E1** cryptographic function, which takes the challenge, its address, and the shared link key.
    - The verifier performs the same calculation and compares the result with the received response. If they match, authentication is successful, and both devices are considered to share a valid key.
    - In mutual authentication, both devices switch roles and verify each other.
- **Vulnerabilities:**
    - **Weak and predefined PINs:** While PINs can be up to 16 bytes long, many devices use short PINs (e.g., "0000", "1234"), making them susceptible to brute-force and eavesdropping attacks.
    - **Device-based authentication:** Bluetooth authenticates devices, not users, meaning anyone with access to a paired device can connect without restrictions.
        - No limit on failed attempts, enabling brute-force attacks.
    - **MITM attacks during pairing:** The traditional challenge-response mechanism is vulnerable.
        - **Secure Simple Pairing (SSP)** reduces risks, but studies show it can still be exploited in certain scenarios.
    - **Optional encryption and weaknesses in E0:** Encryption is not mandatory for all connections. **E0**, Bluetooth’s encryption algorithm, is weak and vulnerable when shorter keys are used.
    - **Additional issues:**
        - It is not possible to define differentiated security policies for various services; the same policies apply uniformly, potentially leaving privileged or “hidden” channels open (such as backchannels or AT commands with elevated access).
        - Vulnerabilities in service coding, especially in RFCOMM, and the use of outdated protocols exacerbate security risks.
        - Some older devices omit the **Security Manager**, reducing security.
        - Once a connection is established, its security is not continuously verified.
        - Bluetooth has limitations in auditing and non-repudiation, making it difficult to track unauthorized access.

**NFC:** Near Field Communication technology that enables data exchange over very short distances (up to 10 cm), providing a physical barrier that limits certain attacks common in other wireless technologies.

- **Security:**
    - **Limited range:** Significantly reduces the risk of remote interception.
    - **Data encapsulation:** Can incorporate protocols like SSL to prevent the transmission of sensitive information in plaintext.
- **Security in Mobile Payments:**
    - **Payment process:** Simulates the protocol of contactless credit/debit cards, based on ISO/IEC 14443 and 7816 standards. The payment terminal communicates with the mobile device via NFC to collect the necessary data for the transaction.
    - **Mobile wallets:**
        - **Android:** Android Pay, Samsung Pay (the latter includes MST for additional compatibility).
        - **iOS:** Apple Pay, natively integrated.
    - **Verification and authentication:** All platforms require user identity verification via PIN or biometrics. Deferred (offline) payments are supported.
    - **Tokenization:** A process that replaces the actual card number with a temporary token during the transaction. The bank generates this token and links it only to the specific purchase, preventing the original data from being stored or exposed on the device or at the merchant.
- **Attacks:**
    - **NFC device spoofing:** Use of hidden NFC chips to interact with devices and exploit known vulnerabilities.
    - **Relay attacks:** Artificially extend the NFC range, enabling real-time MITM attacks.
        - **Risk:** Many NFC devices lack specific mechanisms to detect them.
        - **Impact:** The growing adoption of mobile payments has made these attacks increasingly attractive to attackers.

---

## Security in Android

**Android Architecture:** Composed of five layers, from hardware to applications, facilitating resource abstraction, service management, and secure inter-process communication.

1. **Linux Kernel:** The foundation of the system, directly dependent on the hardware.
    - Manages memory, power, networks, security policies, and shared library support.
    - Evolves alongside the Android platform to adapt to new requirements.
2. **HAL (Hardware Abstraction Layer):** Defines a standardized interface for hardware manufacturers.
    - Abstracts driver-specific details, allowing upper layers to interact with hardware independently.
    - Features are packaged into modules loaded at runtime, ensuring compatibility and flexibility.
3. **System Services:** Exposes core and device-specific functionalities via APIs.
    - **Multimedia Services:** Includes libraries and services for audio and video playback and recording (e.g., Stagefright), supporting multiple formats and codecs.
    - **System Services:** Enables direct interaction with sensors, call management, location, and resources.
        - **Activity Manager:** Manages the activity lifecycle.
        - **Content Providers:** Facilitate data sharing between applications.
        - **Telephony Manager:** Handles voice calls.
        - **Location Manager:** Provides GPS and network-based location services.
        - **Resource Manager:** Controls application resource usage.
    - **Other Services and Libraries:** Includes C/C++ libraries for graphics (Surface Manager, SGL, OpenGL ES), fonts (FreeType), web rendering (WebKit), databases (SQLite), cryptography (OpenSSL), and the C library (libc).
    - **Runtime Services:** Provide the execution environment for applications.
        - Initially based on the Dalvik virtual machine, replaced by ART from Android 5.0 onwards to optimize performance and reduce execution times.
        - Each application runs in an independent Linux process, reinforcing isolation and security.
4. **Inter-Process Communication (Binder IPC):** Enables interaction between processes, each isolated in its own memory space.
    - Binder enhances performance and security by:
        - Using memory references instead of data copies.
        - Providing a C++ remote procedure call (RPC) framework that prevents privilege escalation.
5. **Application Layer:** The user-facing interface.
    - All installed applications reside and run here, each within its own virtual machine instance.
    - Ensures security and isolation between applications, as each process is independent.
- **Version Support:** Android manages app compatibility through an **API level**, an integer identifier that specifies available features in each Android version.
    - Each Android version has a specific API level. When developing an app, a minimum API level is defined for it to function.
    - The **Android framework** provides the tools and functions apps can use, including:
        - **System packages and classes:** A set of functions and libraries to interact with Android.
        - **XML elements in *AndroidManifest.xml***: Essential app configurations, such as required permissions and features.
        - **Permissions system and *intents***: Controls which resources an app can access and how it communicates with others.
    - **Cumulative Updates:** Framework updates add new features without removing older ones, allowing legacy apps to function on newer Android versions.
        - For security reasons, some features may be modified or deprecated.
    - **Android Fragmentation:** The coexistence of multiple Android versions poses a challenge for developers but has not hindered the OS’s market expansion.

**Basic Components:** These are the essential building blocks of an Android application. They operate independently, fulfill specific roles, and have their own lifecycle, which determines how they are created, executed, and destroyed within the system.

- **Activity:** The visual interface that the user interacts with, composed of views and graphical elements that display information and capture actions (touches, gestures, etc.).
    - **Functionality:** Facilitates direct user interaction and enables navigation between different screens by invoking other Activities.
    - **States:**
        - **Active:** In the foreground, interacting with the user.
        - **Paused:** Still visible (e.g., when a dialog appears), where saving data and state is crucial.
        - **Stopped:** No longer visible; the system may remove it to free up memory.
    - **Lifecycle:**
        - **onCreate(Bundle savedInstanceState):** Initializes the Activity, loads the interface, and configures variables.
        - **onPause():** Invoked when the Activity loses focus; ideal for saving state.
        - **onStop():** Called when the Activity is no longer visible, allowing resource cleanup.
        - **onDestroy():** Performs final cleanup and releases resources when the Activity is destroyed.
- **Service:** A component that runs in the background without a user interface, designed for long-running tasks or processes that must continue executing even when the user is not interacting directly.
    - **Functionality:** Performs operations such as playing music, downloading files, or synchronizing data. Allows communication with other components through a client-server model.
    - **Startup Modes:**
        - **STARTED:** Initiated with **startService()**, it continues running until explicitly stopped, even if the application that started it is no longer in the foreground.
        - **BOUND:** Started via **bindService()**, allowing other components to connect to it and communicate through an interface. This mode ends when the connection is closed.
    - **Lifecycle:**
        - **onCreate():** Executes when the Service starts.
        - **onDestroy():** Invoked when the Service ends, either internally with **stopSelf()** or externally using **Context.stopService()**.
- **Content Provider:** A component responsible for managing and sharing data between different applications. It acts as an intermediary, allowing controlled access to read, insert, update, or delete information.
    - **Functionality:** Centralizes data access, regardless of whether the data is stored in an SQLite database, files, or other repositories. Facilitates information reuse without exposing internal storage methods.
    - **Security Control:** Configured through **AndroidManifest.xml** with attributes such as:
        - **android:exported:** Defines whether other applications can access the provider.
        - **android:protectionLevel:** Sets restrictions (e.g., “signature” requires apps to be signed with the same key to access).
    - **Main Methods:** Provide granular control over data access.
        - **query():** Retrieves data.
        - **update():** Modifies existing data.
        - **delete():** Deletes data.
- **Broadcast Receiver:** A component that listens for messages (broadcasts) sent by the system or other applications, informing about global events such as connectivity changes, message arrivals, or completed downloads.
    - **Functionality:** Allows the application to respond to events without needing an active interface, even launching other components (such as Activities or Services) in response.
    - **Lifecycle:** Activates briefly upon receiving a broadcast via the **onReceive()** method and deactivates immediately after execution, having a very short lifecycle.

**Applications in Android:** Applications are primarily developed in Java (although C/C++ can also be used with the NDK) and distributed as APK files.

- **APK:** The installable package that contains:
    - **Compiled code**
    - **Resources:** Images, texts, layouts, etc.
    - **androidManifest.xml:** Defines the app's structure, its components, and permissions.
- **Sandboxing and Isolation:** Android is based on a multi-user Linux system, assigning a unique UID to each application, so it can only access its own files and resources.
    - Each application runs in its own process and in an instance of the virtual machine (originally Dalvik, then ART), ensuring strong isolation between applications.
    - **Least Privilege:** Each app is granted only the permissions strictly necessary for its operation.
- **Interaction and Data Sharing:**
    - Two applications can share the same UID if they are signed with the same certificate, allowing mutual access to their data and, in some cases, running in the same process to optimize resources.
    - Applications must request permissions to access sensitive data (contacts, SMS, storage, camera, Bluetooth, etc.), and these permissions must be approved by the user during installation.
- **androidManifest.xml:** The central file that configures the application, where the following are declared:
    - **Components:** Activities, Services, Content Providers, Broadcast Receivers.
    - **Required permissions:** Internet access, reading contacts, etc.
    - **Minimum API level and hardware/software requirements:** For example, the need for a camera, Bluetooth support, or multitouch display.
    - **External libraries:** Such as Google Maps, which are linked to the app.
- **Intents:** Messaging objects that facilitate asynchronous communication between components, either within the same application or between different applications.
    - **Function:** They allow requesting a specific action (e.g., starting an Activity to dial a number) or executing a Service.
    - **Usage Modes:**
        - **Explicit:** The target component is specified directly.
        - **Implicit:** Android selects the appropriate component based on the **intent filters** declared in the manifest.
    - **Fields of an Intent:**
        - **Action:** The action to be performed (e.g., ACTION_DIAL, ACTION_EDIT).
        - **Data:** Information in URI format (such as a phone number or URL).
        - **Category:** Specifies which components can or should handle the intent (e.g., CATEGORY_BROWSABLE).
        - **MIME type:** Defines the type of data contained (e.g., image/*, text/html).
        - **Target component:** Used in explicit intents to identify the receiving component.
        - **Extras:** Key-value pairs to add additional information (e.g., EXTRA_EMAIL with a list of addresses).
        - **Flags:** Indicators that define the behavior of the intent (e.g., to control the activity stack).

**Security in Android:** Android incorporates multiple security mechanisms at the operating system level and in application development, aimed at reducing the frequency and impact of vulnerabilities and making it easier for developers to create secure apps.

- **Permission Model:** Applications must declare the necessary permissions in **androidManifest.xml** using the `<uses-permission>` tag (e.g., camera, contacts, or location access).
    - **App-Specific Permissions:** Developers can define their own permissions using `<permission>`, with attributes such as: description, icon, label, name, permissionGroup, and protectionLevel.
    - **Component Permissions:** Allow restricting access to specific functions, take priority over the app's general permissions, and are applied during operations like `startActivity()`, `bindService()`, etc.
    - **Runtime Permissions (since Android 6):** Many permissions are requested while the app is in use, allowing the user to accept or deny each request without affecting the overall functionality.
    - **Best Practices:** The principle of Least Privilege is recommended to minimize the requested permissions and, for internal communications, use protection levels such as **signature**.
- **Data Storage:**
    - **Internal Storage:** Data stored here is private for each application and is deleted upon uninstallation. For sensitive information, it is recommended to encrypt it with keys stored in the **KeyStore**.
    - **External Storage:** Includes devices like SD cards or internal memory partitions configured as external.
        - Previously, files in external storage were globally accessible.
        - Recent versions use **Storage Access Framework (SAF)** to control access.
        - Still, sensitive data should not be stored without proper cryptographic measures.
    - **Content Providers:** Provide a structured method for sharing data between apps in a controlled way, allowing granular read and write permissions and avoiding risks like SQL injection.
- **Device Encryption**
    - **Full Disk Encryption (FDE):** Encrypts all user data so that during storage or retrieval, it is protected from unauthorized access.
        - It uses a **passcode** (PIN, password, or pattern) set by the user to encapsulate the encryption key (key wrap), without exposing it outside the device.
        - **Three-Step Process:**
            1. **Generation:** Upon the first boot, a master key (**DEK**) and a 128-bit salt are randomly created.
            2. **Derivation:** The **scrypt** function is used with the passcode and salt to derive an encryption key (**KEK**) and an initialization vector (**IV**), using the **Trusted Execution Environment (TEE)** to sign and reinforce the process.
            3. **Encryption:** Using **dm-crypt and AES-CBC**, the DEK is encrypted with the KEK and IV.
        - **Advantages:** The use of DEK and KEK together allows the password to be changed without re-encrypting the entire memory, as only the KEK is regenerated.
        - **Improvements in Android 5.0:**
            - Devices are encrypted on first boot, and the DEK is stored in a hardware-backed KeyStore (TEE), preventing its extraction.
            - Fast encryption (only of used blocks) to reduce boot time.
            - Support for multiple authentication methods (pattern, PIN, password).
            - Integration with security hardware similar to TrustZone.
    - **File-Based Encryption (FBE):** Introduced in Android 7, allows individual files to be encrypted with different keys, facilitating independent unlocking.
        - **Direct Boot:** Allows the device to boot quickly without decrypting all content by dividing storage into two volumes:
            - **Credential Encrypted:** Accessible only after the user enters their credentials.
            - **Device Encrypted:** Available during boot (direct boot).
- **KeyStore:** Provides a secure container for storing private keys, preventing their extraction without knowing the master password.
    - Stored keys are used in cryptographic operations without being exposed to the system.
    - It is associated with the KeyChain API to manage system credentials.
    - Since Android 4.3, hardware-backed key storage has been provided, significantly increasing the protection of cryptographic material.
- **App Signing:** Ensures that updates and new versions of an app come from the same developer, establishing trust relationships (same-origin policy).
    - APKs must be digitally signed using the JAR format and X.509 certificates.
    - Android uses self-signed certificates, verifying that all entries in the APK are signed with the same certificate set.
    - **Signing Modes:**
        - **Debug:** Used during development, with a certificate automatically generated by the SDK (with a known password). Apps with this signature should not be distributed.
        - **Release:** Requires a certificate created by the developer with strong passwords and secure storage, with an appropriate validity period.
- **Fighting Malware:** There is widespread malware proliferation on Android, capable of making calls or sending messages to premium numbers without consent.
    - **Measures Taken:**
        - **Verify Apps:** Antivirus integrated into Google Play Services that regularly scans installed apps for malware.
        - **Google Play Review:** Strict controls and review processes have significantly reduced infections.
- **SSL/TLS and MITM:** Many Android apps use SSL/TLS for secure communications, but errors in implementation make them vulnerable to MITM attacks.
    - **Common Problems:**
        - Poorly configured trust managers.
        - Apps that ignore SSL/TLS errors, especially when using WebKit.
        - Lack of proper certificate chain and server name verification.
    - **Recommendations:**
        - Implement a custom trust manager that loads a KeyStore with the correct certificates.
        - Update the security provider via Google Play Services (common practice since Android 5.0), to be protected against known exploits.
        - Use certificate pinning techniques to limit trust to specific certificates.
- **Other Security Measures and Best Practices:**
    - **Use of Cryptographic Libraries and Secure Protocols:** It is recommended to use the libraries and protocols integrated into Android, which are tested and evaluated by experts, rather than implementing custom solutions.
        - **SSL/TLS:** Implemented in HttpsURLConnection and SSLSocket (TLS 1.2 is supported since API 16).
        - **Cryptographic Libraries:** *javax.crypto* and *AndroidOpenSSL* for encryption, key negotiation, and authentication (supporting AES, RSA, 3DES, RC2, RC5 in ECB, CBC, CFB, OFB, and CTR modes).
        - **Secure Generators:** SecureRandom for random numbers and KeyGenerator for symmetric keys.
    - **VPN:** Android provides native support for IPsec, XAuth, and VPN clients such as OpenVPN.
    - **WiFi:** Implementation of security protocols like WPA, WPA2 (including IEEE 802.1X/EAP).
    - **Stay Updated:** Use the latest stable versions of protocols and algorithms, as vulnerabilities can be discovered and patched over time.

**Static Analysis of an Android Application:** Focuses on examining the application without executing it, analyzing its source code, file structure, and metadata contained in the APK.

- **Objectives:**
    - Detect potential vulnerabilities in the code.
    - Identify insecure components and configurations.
    - Prepare the groundwork for a deeper dynamic analysis.
1. **Obtaining the APK:**
    - **APK Extractor:** Uses an installed application on the device to list apps and extract the APK file, saving it in an accessible directory (e.g., `/storage/emulated/0/ExtractedApks/<name>`), from where it can be copied via USB.
    - **Android Debug Bridge (ADB):** Allows remote communication with a device or emulator via USB.
        - With developer options and USB debugging enabled, it is possible to list installed packages (using `pm list packages -f`) and extract the APK from the `/data/app/<package_name>/` directory.
        - This method may require root access to reach certain paths.
    - **Download from third parties:** Tools or websites like PlaystoreDownloader, APKPure, or Evozi allow obtaining the APK from the Play Store link. While quick, this method does not guarantee file integrity.
2. **Basic APK Structure:**
    - **AndroidManifest.xml:** A key file in binary XML format that declares the application components, permissions, and hardware and software requirements.
    - **META-INF:** Directory containing APK metadata, including the `MANIFEST.MF` file and the digital signature (e.g., `CERT.RSA`), essential for verifying integrity and authenticity.
    - **resources.arsc:** A file storing precompiled resources (such as strings, styles, and other elements) in binary format.
    - **assets/:** Optional directory where the application stores files and resources accessed via `AssetManager`.
    - **lib/:** Contains native libraries (compiled C/C++ files) used by the application.
    - **res/:** Directory with non-compiled resources (layouts, images, and other graphic files).
    - **classes.dex:** File containing compiled code in Dalvik Executable (DEX) format, executed by the Android virtual machine.
3. **APK Decompilation:**
    - **Apktool:** A cross-platform Java tool that decompresses the APK and extracts its file structure. It converts the binary AndroidManifest.xml into a readable format and generates SMALI code (an assembler-like language), allowing an understanding of the application's flow.
        - Command example: `java -jar apktool_2.3.2.jar d <apk_name>`
    - **Rebuilding:** Apktool also allows recompiling the modified APK, useful for testing and security patch analysis.
4. **Obtaining the Source Code:**
    - **DEX to JAR Conversion:** **dex2jar** is used to convert the `classes.dex` file into a JAR file.
        - Example: `java -jar d2j-dex2jar.jar <apk_name>`
    - **Decompiling to Java:** Tools like **JD-GUI** visualize the Java code contained in the JAR, facilitating the search and analysis of logical flows and potential vulnerabilities.
        - **JADX:** An alternative tool that automates the entire process, allowing direct input of the APK and generating a project with the Java source code.
    - **Limitations:** Reverse engineering may be hindered by advanced obfuscation techniques. In such cases, analyzing the SMALI code is necessary to understand the application's actual functionality.
5. **Analysis Methodology:** Once the APK has been obtained and decompiled, the following elements are analyzed:
    - **Review of AndroidManifest.xml:**
        - **Requested Permissions:** Ensure the app only requests essential permissions for its operation. Critical examples include:
            - **SMS:** `READ_SMS`, `WRITE_SMS`, `SEND_SMS`, `RECEIVE_SMS`.
            - **Calls:** `READ_CALL_LOG`, `WRITE_CALL_LOG`, `ADD_VOICEMAIL`.
            - **Contacts:** `READ_CONTACTS`, `WRITE_CONTACTS`, `GET_ACCOUNTS`.
            - **External Storage:** `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`.
            - **Sensitive Data:** Permissions for microphone access, location, etc.
        - **Security Attributes:**
            - `android:allowBackup="false"`: Prevents backing up the app and its data via ADB.
            - `android:debuggable="true"`: Indicates that the application is in debug mode, which can facilitate arbitrary code execution.
            - **Intent Filters:** Ensure that `android:exported` is configured correctly to prevent unauthorized invocation of components.
    - **Verification of Digital Certificate:** Extract and examine the digital signature to confirm the developer's identity and detect potential relationships between apps signed with the same certificate.
        - **Command example:** `keytool -printcert -file META-INF/CERT.RSA`
    - **Analysis of Application Resources:**
        - **Databases:** Review `.db` files (usually in `/data/data/<package_name>/databases`) with tools like SQLite Browser to identify potential data leaks.
        - **Shared Preferences:** Examine XML files in `/data/data/<package_name>/shared_prefs` for sensitive data stored in plaintext.
        - **File Permissions:** Evaluate read, write, and execute permissions in key app directories to detect insecure configurations.
    - **Source Code Review:**
        - **Plaintext Credentials:** Search for API keys, tokens, passwords, or sensitive information exposed in variables or comments.
        - **Exposed URLs and IPs:** Identify connections to external servers that could be manipulated.
        - **Log Records:** Detect log outputs (e.g., `Log.i()`, `Log.e()`, `System.out.print()`) that could leak sensitive data or debugging details.
        - **Cryptographic Algorithms:** Check for insecure algorithms (e.g., MD5, SHA-1) or incorrect encryption implementations (using Base64 instead of actual encryption).
        - **Executing System Commands:** Review calls to methods like `Runtime.getRuntime().exec()` that could combine with user data, exposing the app to command injections.
        - **Root and Certificate Verification:** Detect functions or libraries that check root status or disable HTTPS certificate validation (e.g., a `HostnameVerifier` that always returns `true`).
    - **Automated Tools:** Use frameworks like **Mobile Security Framework (MobSF)** or **Super Android Analyzer** to accelerate and complement the analysis, generating detailed vulnerability reports.

**Dynamic Analysis:** Evaluates the application's behavior while running, allowing the identification of vulnerabilities that only manifest at runtime.

- **Objectives:**
    - Observe the interaction between components and client-server communication.
    - Monitor file access and application response to events.
    - Detect suspicious behaviors or deviations in the application's logic.
1. **Environment Setup:**
    - **Physical Device:** Provides full interaction with real hardware (sensors, network, etc.), yielding more realistic results.
        - May require root access, full resets, and does not facilitate snapshot creation for repetitive testing.
    - **Emulator (e.g., Genymotion):** Allows the creation of controlled environments with rooted devices, enables snapshots, and is free.
        - Has limitations in hardware interaction (GPS, NFC, etc.) and compatibility with native libraries (especially in x86 emulators).
        - Configure the emulator's network (NAT or Bridge mode) to ensure it is on the same segment as the host running the proxy.
2. **Traffic Interception and Analysis:** Uses **Burp Suite** as a reverse proxy to capture, analyze, and modify network traffic generated by the application.
    - **For Android <7.0:** The Burp certificate must be manually installed on the device (converting the `.der` file to `.cer`), and the WiFi proxy settings must be configured.
    - **For Android ≥7.0:** Due to security enhancements, applications do not trust user-installed certificates.
        - The **AndroidManifest.xml** file must be modified (using the `android:networkSecurityConfig` attribute) to allow user certificates, or alternatively, the Burp certificate can be installed directly into the system via ADB with root privileges.
3. **Monitoring and Retrieving Logs:** Uses **ADB logcat** to extract and view application logs in real time. Filtering by severity levels (e.g., warnings and errors) and using the app’s PID helps focus on relevant information.
4. **Component Interaction:**
    - ADB commands can simulate calls to exposed components to verify if they are adequately protected.
    - Fuzzing techniques (e.g., using the **Drozer** framework) can send unexpected or malicious data to components to detect vulnerabilities in their handling.
5. **Bypassing Countermeasures:** Uses tools like **Frida** to inject code at runtime and modify the application's behavior:
    - **Frida:** Instrumentation tool that allows real-time code injection into the application process to modify its behavior. Its applications include:
        - **Bypassing root detection:** Modifying verification functions to return `false`, preventing the application from detecting it is running in a rooted environment.
        - **Bypassing certificate pinning:** Intercepting and modifying HTTPS certificate verification methods to allow traffic interception without causing errors.
        - **Usage modes:**
            - **Injected agent:** Requires root access to inject the library into the process.
            - **Embedded agent:** Incorporates the Frida Gadget into the APK, enabling instrumentation without root access.
6. **Analysis of Communication with External Servers:**
    - This step is crucial to ensure business logic and backend communication are robust and secure.
    - Session management, input validation, and protection against web vulnerabilities (such as XSS or SQL Injection) are analyzed.
    - Cookie handling (with HTTPOnly and Secure attributes) is reviewed, and HTTPS connections are verified for proper implementation.
7. **Verification of Access to Sensitive Data:**
    - Assess whether the application retrieves critical device data (e.g., IMEI, SIM number) without authorization.
    - Check that the app does not send SMS/MMS without user consent.
    - Review clipboard usage and other channels that may expose sensitive information.

**Vulnerable Applications:** To validate the methodology and refine analysis techniques, it is recommended to use intentionally vulnerable applications.

- **Examples:** GoatDroid, Diva, InsecureBanking2, DVHA, CrackMe.
- These allow practice in both static and dynamic analysis, facilitating the identification of issues such as misconfigured permissions, data leaks, SSL/TLS weaknesses, code injection, root detection, and certificate pinning flaws.

---

## iOS Security

**System Security in iOS:** Implements a comprehensive security model that protects the operating system, applications, data, and communications. From boot-up to biometric operations, iOS uses strict cryptographic verifications and dedicated hardware to ensure system integrity and confidentiality.

- **Secure Boot → Chain of Trust:** The boot process starts in the ROM, which acts as the root of trust by containing Apple’s public key. Each boot component (LLB, iBoot, kernel, and radio firmware) must be digitally signed with Apple’s private key.
    - If any verification fails, the device enters DFU mode or recovery mode ("Connect to iTunes"), requiring restoration via a PC or Mac.
- **System Software Authorization:**
    - During updates, iTunes or the device itself connects to Apple’s servers and sends metrics such as checksums, version, ECID, and a nonce for each component.
    - The server validates that the firmware is the latest authorized version for that model, preventing the installation of outdated or tampered firmware.
- **Secure Enclave:** A coprocessor present in devices with A7 or newer processors, dedicated to managing cryptographic keys and sensitive operations in isolation.
    - Never exposes keys or biometric data, using its own memory and a secure random number generator to create keys and establish encrypted session negotiations with the biometric sensor.
    - Converts Touch ID biometric data into irreversible mathematical representations, without storing raw images.
- **Touch ID:**
    - **Authentication and Unlocking:** Allows quick device unlocking through fingerprint recognition.
        - The system requires the security passcode in specific cases (reboot, prolonged inactivity, multiple failed attempts, or when registering new fingerprints).
    - **Purchases and Transactions:** When authorizing a purchase, Touch ID generates a temporary token that, along with a nonce, is signed by the Secure Enclave to confirm the transaction to Apple.
    - **Integration and Privacy:** Provides secure APIs so third-party apps can authenticate users without exposing biometric data, ensuring that sensor-to-enclave communication remains encrypted and private.

**Data Encryption and User Data Protection**: iOS implements robust protection by combining hardware and software cryptographic mechanisms to ensure data confidentiality and integrity, even in cases of unauthorized access or device compromise.

- **Hardware**
    - **Integrated Encryption Engine:** Uses AES-256 to transparently encrypt communication between memory and flash storage, ensuring all written and read data is protected.
    - **Unique Identifiers (UID and GID):** These keys are embedded in the chip and inaccessible to software.
        - **UID:** A unique identifier burned into the processor during manufacturing, exclusive to each device and not stored elsewhere, creating a unique encryption environment.
        - **GID:** A group identifier shared among devices of the same model, used for general operations (such as firmware validation).
    - **Additional Key Generation:** The main processor uses a CTR_DRBG-based generator, leveraging entropy from timing measurements to create additional cryptographic keys.
        - Secure Enclave has its own hardware-based random number generator, enhancing security by generating keys and performing operations without external intervention.
    - **Secure Key Erasure:** iOS implements mechanisms to securely erase memory blocks containing sensitive keys when they are no longer needed or when the device is locked, preventing residual data exposure.
- **Passcode Protection:** Setting a passcode (alphanumeric or at least 4 digits) automatically enables device data protection.
    - **Entropy Contribution:** The passcode is integrated into encryption key generation, binding it to the device’s UID, making brute-force attacks significantly harder.
    - **Attempt Delays:** A calibrated delay (~80 ms) is introduced between failed attempts, greatly increasing the time required for brute-force attacks.
    - **Progressive Response:** Implements measures where, after a certain number of failed attempts, the device content is automatically erased to prevent attacks.
    - **Touch ID Integration:** Allows for longer and more secure passcodes while maintaining usability.
    - **Operations within Secure Enclave:** On devices with A7 or newer processors, failed attempts are managed within the Secure Enclave, enforcing five-second pauses between consecutive attempts to mitigate attacks.

**File Protection Classes in iOS:** Uses a robust cryptographic hierarchy that applies multiple layers of encryption. This ensures that, unless specific conditions are met (e.g., the device is unlocked), file content remains inaccessible. Protection is achieved by combining a unique key for each file (file key) with class keys that "wrap" the file key, all integrated with device identifiers and authentication mechanisms.

- **Protection Hierarchy:** The encryption structure can be visualized as a chain: `Passcode → (ECID → (Class Key C → (File Key F → File Data)))`
    - **File Key (F):**
        - Each file is encrypted independently using a unique random key.
        - Without this F key, decrypting file content is impossible, acting as the first security barrier.
    - **Class Keys (C):**
        - The F key is encrypted using a class key (C), which controls file access based on the device’s state.
        - The system must decrypt the F key using C before granting data access.
        - Access to class keys depends on conditions verified by the Secure Enclave, such as device unlocking or Touch ID authentication.
    - **Device ID-Derived Key (ECID):**
        - All class keys are further encrypted with a key derived from the device's unique identifier (ECID).
        - This ensures that without knowing the ECID, class keys cannot be obtained, adding a third layer of security.
    - **User Passcode:**
        - In certain cases, class keys are re-encrypted using the user’s passcode.
        - Thus, recovering the F key is only possible if the correct passcode is entered, reinforcing protection.
- **Protection Class Change:** The architecture allows updating a file’s protection level without requiring full re-encryption:
    - A file encrypted with the F key, itself encrypted with class key C1, can be updated.
    - The F key is decrypted using C1 and then re-encrypted with a new class key C2.
- **Initialization Vector:** Calculated from the position of each file block and encrypted with an SHA-1 hash of the F key, ensuring that each block is uniquely encrypted.
- **Metadata:** Includes a copy of the F key encrypted with the class key and the class identifier, protected with a generic file system key established during device initialization.
    - By reading metadata, the system determines which class key (C) is required to decrypt the F key.
- **Secure Erasure in iOS:** Settings → General → Reset → Erase All Content and Settings.
    - Securely erases the memory portion containing the file system access keys.
    - Destroys metadata and, consequently, the F key, making files permanently inaccessible.
    - In corporate environments, this process can be triggered remotely via Mobile Device Management (MDM).

**Security Levels in iOS File Storage:** Each file is protected through a layered encryption system that defines when and how information can be accessed, depending on the device’s state (locked, unlocked, etc.) and other security conditions. This approach ensures that even if a device is lost or stolen, user data remains inaccessible without proper authentication.

- **NSFileProtectionComplete:** Files can only be read or modified when the device is unlocked.
    - During initial setup, a class key is generated from the passcode and the device’s unique identifier (UID).
    - When the device locks, the class key is removed from memory, preventing data access until it is unlocked again.
- **NSFileProtectionCompleteUnlessOpen:** Files that have already been opened remain accessible even if the device locks; once closed, they become inaccessible until the next unlock.
    - A cryptographic process (e.g., ECDH negotiation over Curve25519) generates a volatile key (D).
    - The D key is combined with the specific file key (F) to form a "signature" (using an SHA-256 hash of D * F).
    - This signature allows the F key to be decrypted while the file is open; once closed, the device must be unlocked to regain access.
- **NSFileProtectionUntilFirstUserAuthentication:** Files are fully protected until the user unlocks the device for the first time after a reboot.
    - After the first unlock, the security key remains in memory, allowing file access even if the device is later locked, until it is powered off completely.
- **NSFileProtectionNone:** Files are always accessible without additional restrictions based on the device’s state, though they remain encrypted.
    - The specific file key (F) is protected only by a key derived from the device’s UID, without additional unlock controls.
    - While access is unconditional, automatic deletion mechanisms ensure that, in the event of a full wipe, data becomes permanently inaccessible.

**Secure Storage of Passwords and Identifiers in iOS:** A centralized and robust mechanism, managed by the **securityid** daemon, securely stores passwords, tokens, and session identifiers.

- **Keychain Structure and Management:**
    - **Database and Service:**
        - Data is stored in an SQLite database, which only **securityd** has direct access to.
        - Applications interact with the Keychain through official APIs, and only apps signed with the same group identifier can share keys.
    - **Accessibility Classes (KSecAttrAccessible):** These classes define when and how Keychain items can be accessed based on the device’s state:
        - **KSecAttrAccessibleWhenUnlocked:**
            - Data is accessible only when the device is unlocked.
            - The access key is wrapped with the passcode and removed when the device locks.
        - **KSecAttrAccessibleAfterFirstUnlock:**
            - Data remains available after the first unlock, even if the device locks again, until it is powered off.
            - Ideal for background applications.
        - **KSecAttrAccessibleWhenPasscodeSet:**
            - Active only if the device has a passcode set.
            - If the passcode is removed or reset, the key is discarded, rendering associated data unusable.
        - **KSecAttrAccessibleAlways:**
            - Data is always accessible.
            - While still encrypted, this is not recommended for sensitive information and is limited to specific use cases (such as the SIM PIN or iCloud ID).
        - **"ThisDeviceOnly" Variants:** Starting from iOS 8, non-migratory versions (e.g., `KSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`) prevent synchronization or restoration on other devices, ensuring data remains only on the original device.
- **ACLs and Keychain Access Control:**
    - Additional security policies can be enforced using Access Control Lists (ACLs) to require, for example, Touch ID or passcode entry before granting access.
    - These verifications occur within the Secure Enclave, ensuring keys are only delivered under strictly secure conditions.
- **Accessing Safari Passwords via API:**
    - Safari exposes the **SecRequestSharedWebCredential** and **SecAddSharedWebCredential** APIs to allow third-party apps access to stored credentials.
    - Apps must declare the **com.apple.developer.associated-domains** permission with a list of associated domains, and websites must provide a signed file ("apple-app-site-association") validating the relationship.
- **Cryptographic Key Repositories (Separate from User Keychain):** iOS maintains dedicated repositories for storing cryptographic keys essential for global system security:
    - **System Key Repository:**
        - Stores keys used by the OS when the device is unlocked.
        - Stored in an encrypted `.plist` file, with its key held in a secure, wipeable memory zone.
    - **Backup Key Repository (iTunes):**
        - When backing up with iTunes, unique keys encrypt backup contents.
        - Non-migratory elements (UID-based) remain protected.
        - Migratory elements are encrypted using a key derived from the backup password via PBKDF2 (10,000 iterations).
    - **Custody Key Repository:**
        - A copy of the repository storing access keys for protection classes, encrypted with a randomly generated key from a remote server.
        - Allows synchronization with iTunes or MDM servers without directly exposing the key.
    - **iCloud Backup Key Repository:**
        - Similar to the iTunes repository but designed for iCloud.
        - Keys are protected similarly to NSFileProtectionCompleteUnlessOpen and managed to prevent sensitive data synchronization across devices.

**iOS Application Security:** Essential for protecting user data and maintaining ecosystem integrity. Apple enforces multiple layers of protection to ensure that all code, whether system or third-party, is signed, validated, and executed in isolated environments, making it difficult to inject malicious or altered code.

- **Application Code Signing:**
    - **Chain of Trust:**
        - Each component (firmware, kernel, apps) must be signed with Apple-issued certificates.
        - The kernel verifies these signatures in real time, blocking unauthorized or modified code.
    - **Ecosystem Control:**
        - Developers must be registered in the iOS Developer Program to obtain valid certificates.
        - Each certificate includes a **Team ID** that links apps to a verified developer and restricts the use of libraries.
    - **Impact:** All code executed in iOS has been validated, making it difficult to create malicious applications and ensuring that any system code alterations are detected.
- **Internal Application Control:**
    - **iOS Developer Enterprise Program (iDEP):**
        - Allows organizations to develop and privately distribute internal apps.
        - Apple verifies the entity’s authenticity (via a DUNS identifier) and issues a signed **provisioning profile** (`.plist` file).
    - **Provisioning Profile:**
        - Contains App IDs, entitlements (specific permissions), and authorized device identifiers.
        - Ensures that only authorized organization devices can install and execute internal apps.
- **Runtime Process Security:**
    - **Sandboxing:** Each app runs in an isolated environment with a unique base directory, preventing direct access to other apps' data.
    - **System Protection:**
        - System code runs in read-only mode with limited privileges (e.g. under the “mobile” user).
        - Entitlements in `.plist` files control access to sensitive functions and prevent unauthorized privilege escalation.
    - **Escalation Prevention:** Similar to the `sudoers` file in Linux, mechanisms prevent apps from executing operations with root privileges.
    - **Address Space Layout Randomization (ASLR):**
        - ASLR randomizes executable code locations, libraries, and data structures, reducing the effectiveness of exploits relying on fixed addresses.
        - Xcode compiles apps with ASLR enabled by default.
    - **eXecute Never (XN) Technology:**
        - ARM processors in iOS mark memory pages as non-executable, preventing injected code execution.
        - The kernel dynamically enforces controls to block execution attempts in unauthorized memory regions.
    - **Application Extensions:**
        - Apps can include extensions (widgets, custom keyboards, sharing actions, etc.) that run in isolated processes with their own entitlements.
        - Extensions within the same app inherit permissions, while those from different apps only have their assigned permissions.
    - **App Groups:**
        - Enable apps and their extensions from the same developer to share data and resources through a common container.
        - Configured in the developer portal, preventing identifier collisions and facilitating secure sharing of preferences and keys.

**Network Communication Security in iOS:** Employs a combination of robust protocols, advanced configurations, and techniques to minimize data exposure, ensuring that both traffic and interactions with servers remain secure and authenticated.

- **Service Hardening:** Unnecessary services (e.g., Telnet, SSH) are disabled or removed to limit potential attack vectors.
- **SSL/TLS Security:**
    - iOS supports **SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, and DTLS**.
    - Native apps like **Mail and Calendar** use these protocols to encrypt and authenticate communications.
    - Apple continuously improves implementations to address historical vulnerabilities in SSL/TLS.
- **VPN Support:**
    - iOS supports multiple VPN protocols, including:
        - **SSL VPN** (used by Juniper, Cisco, OpenVPN).
        - **IPSec**, which supports authentication via passwords, **RSA SecurID**, CRYPTOCard, certificates, or shared secrets.
        - **L2TP/IPSec** and **PPTP** (legacy support for additional authentication options).
    - Advanced VPN features:
        - **Per-App VPN**: Routes traffic from specific apps through a VPN tunnel.
        - **On-Demand VPN**: Automatically triggers a VPN connection based on network conditions or domain rules.
        - **Always-On VPN (iOS 8+)**: Ensures that all traffic, especially on public networks, is routed through a corporate VPN.
- **WiFi Security:**
    - iOS supports modern Wi-Fi security standards, with **WPA2-Enterprise** being the most robust for corporate environments.
    - Supports multiple authentication mechanisms (**EAP-TLS, EAP-TTLS, PEAP, EAP-SIM, etc.**) for secure enterprise network configurations.
    - **Randomized MAC Addresses (PNO/ePNO):**
        - **Preferred Network Offload (PNO)** and **enhanced PNO (ePNO)** allow iOS to scan for known Wi-Fi networks while in sleep mode.
        - Since **iOS 8**, randomized MAC addresses are used for these requests, making device tracking harder and improving user privacy.
- **AirDrop and File Sharing Security:**
    - **AirDrop** uses **Bluetooth Low Energy (BLE) and an ad hoc Wi-Fi connection** to transfer files without requiring an internet connection.
    - **Security Mechanisms:**
        - Generates a **2048-bit RSA identifier** and an identity hash based on the user's Apple ID.
        - By default, AirDrop only allows transfers from contacts but can be configured to accept files from anyone.
        - Devices authenticate each other by exchanging hashes, establish an ad hoc connection via **Bonjour**, and negotiate a **TLS-encrypted** transfer with certificate validation.

**Apple Pay:** Mobile payment solution that enables secure and simple transactions on compatible devices (since iPhone 6). It combines hardware and software to ensure that each payment is executed reliably, protecting the user’s financial data through cryptography and rigorous authentication controls.

- **Key Components:**
    - **Secure Element (SE):**
        - A certified chip that implements Java Card and meets financial standards.
        - Acts as a “black box” that securely stores and processes card data without exposing it to other device components.
    - **NFC Controller:** Manages NFC communication between the processor, the SE, and the point-of-sale terminal (TPV), ensuring that data exchange is direct and encrypted.
    - **Passbook:** An application that stores and manages credit and debit card information, displaying transaction details, banking information, and privacy policies in an intuitive manner for the user.
    - **Secure Enclave and Touch ID:**
        - Work together to authenticate the user.
        - The Secure Enclave communicates directly with the Touch ID sensor, initiating the payment process only after a valid biometric recognition.
    - **Apple Pay Servers:** Manage the status of the cards and banking data stored in the SE, encrypt payment credentials, and coordinate transactions with online payment platforms.
- **Card Enrollment and Storage:** When the user adds a card, the information is securely sent to the bank along with additional user and device data.
    - **Device Account Number (DAN):** An encrypted token generated by the bank that replaces the card's actual number and is stored in the SE, ensuring that sensitive information does not reside on the device or on external servers.
- **Payment Procedure:**
    - **Payment at a POS Terminal:**
        - The SE contains certified mini-applications that process card data and internally generate an encrypted payment message.
        - After authenticating the user via Touch ID or passcode, the NFC controller sends this message directly to the POS terminal through a dedicated bus, preventing other components from accessing the information.
    - **Online Payment from an App:**
        - The SE encrypts the payment response and sends it, with an additional layer of encryption, to the Apple Pay servers, which then relay it to the corresponding payment platform.
        - Once the transaction is verified by the bank, the payment is finalized and the user is notified.
- **Apple Pay Data Deletion:**
    - Using “Find My iPhone,” the owner can request the remote deletion of Apple Pay data.
    - This process destroys the encryption key that enables secure communication between the Secure Enclave and the SE, invalidating all payment data and ensuring that, even in the event of theft, sensitive information cannot be recovered.

**Security Breaches in the iOS Ecosystem:** Over the years, vulnerabilities and methods to bypass iOS security have been discovered, many of which have already been remedied through updates. Understanding these cases is crucial to grasp how the system’s defenses have been reinforced.

- **Jailbreaking:**
    - **Description:** It involves removing the restrictions imposed by Apple by modifying the kernel.
    - **Impact:** It grants full access to the file system, allows the installation of unauthorized apps, and enables firmware modification.
    - **Attack Vectors:** Exploitation of flaws in the boot ROM to break the chain of trust and errors in memory management that facilitate privilege escalation.
    - **Consequence:** It significantly reduces the device’s security, allowing malicious applications to operate without restrictions.
- **Poor Implementation of Cryptographic Classes in APIs:**
    - **Description:** Some developers have incorrectly used the CommonCrypto API.
    - **Specific Case:** The omission or improper initialization of the initialization vector (IV) in symmetric encryption, for example, setting it to zero, which weakens encryption and facilitates cryptographic analysis that can expose the key.
    - **Consequence:** Apps developed following erroneous examples may be vulnerable, although this issue does not affect file system encryption, which uses IVs generated from SHA-1 hashes of the keys.
- **Inadequate Use of Protection Classes:**
    - **Description:** Storing sensitive information (such as usernames and passwords) in .plist files without using the appropriate keychain APIs.
    - **Consequence:** The data becomes exposed to attacks, such as extraction through reverse engineering of an iTunes backup.
    - **Recommendation:** Always use keychain APIs for managing passwords and identifiers instead of simple configuration files.
- **“goto fail;” Bug:**
    - **Description:** In iOS 7, a critical error in SSL/TLS validation occurred due to a duplicated line (“goto fail;”) that omitted an essential certificate check.
    - **Impact:** It allowed Man-In-The-Middle (MITM) attacks, facilitating the interception and modification of secure communications.
    - **Lesson:** This incident underscores the importance of meticulous review and rigorous testing in cryptographic implementations, as a simple error can severely compromise security.
- **Predictable Random Number Generator in iOS 7:**
    - **Description:** The modification of the pseudo-random number generator in iOS 7, intended to improve entropy, turned out to be less robust, generating only 2^19 different values and repeating after 2^17 iterations.
    - **Impact:** Predictability reduces the effectiveness of mechanisms that rely on randomization, such as memory protection, which could facilitate the exploitation of vulnerabilities in memory management and the execution of arbitrary code, thereby compromising kernel security.

**iOS Mobile Application Analysis:** Identify vulnerabilities and configuration errors, as well as evaluate the robustness of the implemented security measures.

- **Testing Environment:** To conduct the analysis, a setup must be configured that allows extraction, analysis, and modification of the applications. The minimum requirements include:
    - A computer (Windows or Linux) with administrator privileges.
    - A WiFi network.
    - A virtual or physical machine running macOS.
    - An iOS device with jailbreak (to facilitate data extraction and manipulation).
- **Key Tools:**
    - **Extraction and Manipulation:** Cydia, OpenSSH, IPAinstaller.
    - **Reversing and Static Analysis:** Class Dump, Radare2 Suite, Hopper, Clutch, Dumpdecrypted, Keychain Dumper.
    - **Instrumentation and Bypass:** Frida, Liberty Lite, iOS SSL Kill Switch 2.
    - **Other Utilities:** BigBoss Tools, adv-cmds, Substrate, AppSync, Needle Framework.
    - **Traffic Analysis:** Burp Suite Proxy.

**Static Analysis:** Examine the contents of the IPA file without executing the application, aiming to identify vulnerabilities, review configurations, and extract relevant information.

- **IPA File (iOS App Store Package):** A compressed container (ZIP format) that includes the binary, configuration files, libraries, and resources.
    - **Acquisition:** It can be obtained via iTunes (synchronization or backup) or through third-party tools (for example, AltDeploy for devices without jailbreak).
    - **Key Structure:**
        - **/Payload/Application.app:** Contains the compiled ARM binary and static resources.
        - **Info.plist:** A configuration file with data such as bundle ID, version, name, etc.
        - **iTunesArtwork & iTunesMetadata.plist:** Graphical information and metadata (copyright, developer).
        - **Additional Resources:** Directories with images, text strings, sound files, etc
- **Location on the Device:**
    - **Installed Applications:** `var/mobile/Containers/Bundle/Application/[UUID]/Application.app`
    - **App Data:** Subdirectories (Documents, Library, tmp) within `var/mobile/Containers/Data/Application/[UUID]/`
- **Stored Information:**
    - **Configuration Files (.plist):** Can be converted to XML (using `plutil`) to facilitate analysis.
    - **Databases:** Files with extensions *.sqlite, *.db, or *.dat, extracted via SFTP and analyzed with tools such as DB Browser for SQLite.
    - **Keychain:** Stores sensitive data (tokens, passwords, keys) and is examined using tools like Keychain Dumper or Needle Framework.
    - **Session Cookies:** Located in `Cookies.binarycookies`, extracted with Python scripts or using the Needle framework.
- **Binary Analysis:**
    - **Encryption:** Binaries downloaded from the App Store are usually encrypted; the “cryptid” field is verified with `otool` (1 = encrypted, 0 = not encrypted).
    - **Decryption:** Tools like Clutch, Dumpdecrypted, or Frida-ios-dump (requires jailbreak and SSH) are used to decrypt the binary.
    - **Information Extraction:**
        - **Radare2 (rabin2):** To obtain details of the binary (symbols, strings, architecture). Example commands:
            - `rabin2 -I <APP>` for general information.
            - `rabin2 -s <APP>` to list symbols.
        - **Class Dump:** Using Class Dump or Clutch to extract the list of classes and methods.
        - **Reversing:** Detailed analysis of the assembly code and internal logic is performed with Hopper.
- **Analysis Frameworks:**
    - **Passionfruit:** A black-box tool for analyzing iOS apps (compatible with devices without jailbreak) that identifies encryption, security flags (PIE, ARC, stack canary) and allows visualization of databases, .plist files, and the Keychain.
    - **Brida:** A Burp Suite extension that acts as a bridge between Burp and Frida to manipulate the traffic between the application and services.

**Dynamic Analysis:** Evaluate the application's real-time behavior, ensuring that data transmission and communication with servers are secure.

- **Objectives:**
    - Confirm that the application adequately protects information transmission, preventing the exposure of sensitive data.
    - Assess the correct implementation of security mechanisms in traffic, such as SSL/TLS.
- **Environment Setup:**
    - **Physical Device:** Offers more realistic results (full hardware access), although it may require a jailbreak and does not allow snapshots.
    - **Emulator (e.g., Genymotion):** Facilitates the creation of rooted devices and snapshots, although they may present limitations with sensors and compatibility with native libraries.
    - **Network Configuration:** It is essential that the device or emulator is on the same network segment as the host running the proxy.
- **Intercepting HTTP/HTTPS Traffic with Burp Suite:** Configure it as a reverse proxy to capture and analyze requests and responses.
    1. Launch Burp Suite on your computer and configure the proxy (IP and port).
    2. On the iOS device, configure the WiFi network to use that proxy.
    3. From the device's browser, access `http://burp` and download the CA certificate.
    4. Install the certificate on the device; from iOS 10 onward, it must be manually activated.
- **Bypassing Security Controls:**
    - **Common Controls:**
        - **SSL Pinning:** Prevents interception of encrypted traffic.
        - **Jailbreak Detection:** Prevents analysis on modified devices.
    - **Tools and Techniques:**
        - **SSL Kill Switch 2:** Disables SSL certificate verification to allow traffic interception.
        - **Liberty Lite:** Hides the jailbreak status.
        - **Frida:** Allows injection of JavaScript code at runtime to “hook” critical functions (e.g., jailbreak detection or SSL pinning) and modify their return values.
            - **Example:**
                
                ```jsx
                javascript
                CopiarEditar
                Java.perform(function () {
                    var JailbreakDetection = Java.use('<java_package>.utils.RootUtil');
                    JailbreakDetection.isJailbroken.implementation = function() {
                        console.log("Bypassing jailbreak detection");
                        return false;
                    };
                });
                ```
                
- **Monitoring and Logs:** **ADB logcat** is used to capture real-time logs, filtering by severity levels and PID to focus on the analyzed application.
- **Evaluation of Communication with External Servers:** The analysis reviews session management, input validation, protection against web vulnerabilities (XSS, SQL Injection), and the correct handling of HTTPS.
- **Verification of Sensitive Data Access:**
    - Assess whether the application extracts critical data (IMEI, SIM number) or sends SMS/MMS without authorization.
    - Evaluate clipboard management and other potential channels for information leakage.

**Vulnerable Application:**

- **Damn Vulnerable iOS Application (DVIA):** An app intentionally designed with vulnerabilities so that pentesting professionals and students can practice their iOS application security analysis skills.
    - It allows experimenting with bypass techniques (e.g., via Frida) and evaluating security controls such as jailbreak detection and SSL pinning.