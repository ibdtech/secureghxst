
import sqlite3
import json
import time
import random
import os
import sys
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    from rich.text import Text
except ImportError:
    print("ERROR: Required package 'rich' not found.")
    print("Install it with: pip install rich")
    sys.exit(1)

console = Console()

MISSIONS = [
    {
        "id": 1,
        "day": 1,
        "title": "NETWORK_RECONNAISSANCE",
        "domain": "Network Security",
        "brief": "Intel reports show weird traffic on TCP ports. Figure out what's happening by looking at network protocols and port numbers.",
        "questions": [
            {
                "scenario": "SCANNING TARGET PORTS...\nYou found some strange traffic on port 443.",
                "question": "Which protocol runs on port 443?",
                "options": ["A) HTTP", "B) HTTPS", "C) FTP", "D) SSH"],
                "correct": "B",
                "explanation": "Port 443 is for HTTPS - that's HTTP with encryption using TLS/SSL. You need to know your ports for this exam."
            },
            {
                "scenario": "INTERCEPTING NETWORK PACKETS...\nCleartext credentials showing up in your packet capture.",
                "question": "Which protocol sends data in cleartext and shouldn't be used?",
                "options": ["A) HTTPS", "B) SSH", "C) Telnet", "D) SFTP"],
                "correct": "C",
                "explanation": "Telnet (port 23) sends everything in plaintext, including passwords. Use SSH (port 22) instead."
            },
            {
                "scenario": "DNS QUERY ANALYSIS...\nLooks like someone's trying to poison the DNS.",
                "question": "What port does DNS use?",
                "options": ["A) 25", "B) 53", "C) 80", "D) 110"],
                "correct": "B",
                "explanation": "DNS runs on port 53 for both TCP and UDP. UDP 53 handles queries, TCP 53 handles zone transfers."
            },
            {
                "scenario": "EMAIL SERVER COMPROMISE DETECTED...\nChecking mail server ports to find how they got in.",
                "question": "Which port is used for secure email transmission (SMTPS)?",
                "options": ["A) 25", "B) 110", "C) 465", "D) 143"],
                "correct": "C",
                "explanation": "Port 465 is SMTPS. Port 25 is regular SMTP (no encryption), 110 is POP3, and 143 is IMAP."
            },
            {
                "scenario": "REMOTE ACCESS ATTEMPT BLOCKED...\nFirewall logs showing tons of connection attempts on port 3389.",
                "question": "What service uses port 3389?",
                "options": ["A) SSH", "B) RDP", "C) VNC", "D) Telnet"],
                "correct": "B",
                "explanation": "Port 3389 is RDP - Remote Desktop Protocol for Windows. Attackers love this port."
            }
        ]
    },
    {
        "id": 2,
        "day": 2,
        "title": "WIRELESS_INFILTRATION",
        "domain": "Network Security",
        "brief": "Corporate wifi is acting weird. Check out wireless security and figure out what's wrong with the encryption.",
        "questions": [
            {
                "scenario": "SNIFFING WIRELESS TRAFFIC...\nOld encryption showing up. This network is screwed.",
                "question": "Which wireless encryption is broken and should never be used?",
                "options": ["A) WPA2", "B) WPA3", "C) WEP", "D) AES"],
                "correct": "C",
                "explanation": "WEP is completely broken - can crack it in minutes. Always use WPA2 or WPA3."
            },
            {
                "scenario": "ANALYZING AUTHENTICATION HANDSHAKE...\nEnterprise network detected. Checking how auth works.",
                "question": "What does WPA2-Enterprise use for authentication?",
                "options": ["A) Pre-shared key", "B) 802.1X with RADIUS", "C) MAC filtering", "D) WPS PIN"],
                "correct": "B",
                "explanation": "WPA2-Enterprise uses 802.1X with a RADIUS server. WPA2-Personal just uses a shared password."
            },
            {
                "scenario": "ROGUE ACCESS POINT DETECTED...\nSomeone set up a fake AP with the same name as ours.",
                "question": "What's this wireless attack called where you create a fake AP?",
                "options": ["A) Deauth attack", "B) Evil twin", "C) Jamming", "D) WPS attack"],
                "correct": "B",
                "explanation": "Evil twin means setting up a fake access point that looks legit to steal traffic."
            },
            {
                "scenario": "BLUETOOTH VULNERABILITY SCAN...\nNearby devices are accepting connections without checking who's connecting.",
                "question": "Which Bluetooth attack sends unwanted messages to devices?",
                "options": ["A) Bluejacking", "B) Bluesnarfing", "C) Bluebugging", "D) Bluesmack"],
                "correct": "A",
                "explanation": "Bluejacking sends spam messages. Bluesnarfing steals your data. Bluebugging takes control."
            },
            {
                "scenario": "WPS PIN BRUTE FORCE ATTEMPT...\nTesting if the router's WPS is vulnerable.",
                "question": "Why is WPS considered insecure?",
                "options": ["A) Uses weak encryption", "B) 8-digit PIN can be brute forced", "C) Broadcasts SSID", "D) Requires physical access"],
                "correct": "B",
                "explanation": "WPS uses an 8-digit PIN that can be cracked in hours because of how it validates. Turn WPS off."
            }
        ]
    },
    {
        "id": 3,
        "day": 3,
        "title": "MALWARE_ANALYSIS_LAB",
        "domain": "Threats and Attacks",
        "brief": "Suspicious file in the exec's downloads folder. Analyze the malware and figure out what type it is before it runs.",
        "questions": [
            {
                "scenario": "ANALYZING EXECUTABLE BEHAVIOR...\nThis thing is copying itself across network shares without anyone clicking anything.",
                "question": "What malware spreads automatically without user interaction?",
                "options": ["A) Virus", "B) Worm", "C) Trojan", "D) Rootkit"],
                "correct": "B",
                "explanation": "Worms spread themselves across networks. Viruses need a host file and someone to run it."
            },
            {
                "scenario": "CRYPTOGRAPHIC ANALYSIS COMPLETE...\nAll the files got encrypted with .locked extension. Found a ransom note.",
                "question": "What malware encrypts files and demands payment?",
                "options": ["A) Spyware", "B) Adware", "C) Ransomware", "D) Keylogger"],
                "correct": "C",
                "explanation": "Ransomware encrypts your files and wants money (usually crypto) for the decryption key."
            },
            {
                "scenario": "KERNEL-LEVEL DETECTION EVASION...\nThis malware is hiding deep in the OS.",
                "question": "What malware operates at kernel level to hide?",
                "options": ["A) Trojan", "B) Rootkit", "C) Backdoor", "D) Logic bomb"],
                "correct": "B",
                "explanation": "Rootkits work at kernel level to hide malware and processes. Really hard to detect and remove."
            },
            {
                "scenario": "KEYSTROKE CAPTURE DETECTED...\nProgram is logging every key press including passwords.",
                "question": "What records keystrokes to steal info?",
                "options": ["A) Keylogger", "B) Screen scraper", "C) Packet sniffer", "D) Session hijacker"],
                "correct": "A",
                "explanation": "Keyloggers record what you type to grab passwords and credit cards. Can be hardware or software."
            },
            {
                "scenario": "TRIGGER CONDITION ANALYSIS...\nMalicious code sitting dormant, waiting for a specific date or event.",
                "question": "What malware only executes when certain conditions are met?",
                "options": ["A) Worm", "B) Virus", "C) Logic bomb", "D) RAT"],
                "correct": "C",
                "explanation": "Logic bombs wait for a trigger like a date or event. Classic example is a fired employee setting one to go off after they leave."
            }
        ]
    },
    {
        "id": 4,
        "day": 4,
        "title": "SOCIAL_ENGINEERING_DEFENSE",
        "domain": "Threats and Attacks",
        "brief": "Employees getting hit with phishing attempts. Learn to spot social engineering and teach the team what to look for.",
        "questions": [
            {
                "scenario": "EMAIL FORENSICS IN PROGRESS...\nUrgent email from 'CEO' wanting an immediate wire transfer. Sender is ceo@comp4ny.com",
                "question": "What's this attack where fake emails look like they're from executives?",
                "options": ["A) Phishing", "B) Whaling", "C) Vishing", "D) Pharming"],
                "correct": "B",
                "explanation": "Whaling targets big fish like executives. Regular phishing is generic, vishing is phone calls."
            },
            {
                "scenario": "VOICEMAIL THREAT DETECTED...\nSomeone calling claiming to be IT and asking for a password reset.",
                "question": "What's a phone-based social engineering attack called?",
                "options": ["A) Phishing", "B) Smishing", "C) Vishing", "D) Spoofing"],
                "correct": "C",
                "explanation": "Vishing is voice phishing - using phone calls. Smishing uses text messages."
            },
            {
                "scenario": "PHYSICAL SECURITY BREACH...\nUnauthorized person followed an employee through the secure door.",
                "question": "What's it called when someone follows you through a secure door?",
                "options": ["A) Tailgating", "B) Shoulder surfing", "C) Dumpster diving", "D) Pretexting"],
                "correct": "A",
                "explanation": "Tailgating (or piggybacking) is following someone through a door. Mantraps stop this."
            },
            {
                "scenario": "FABRICATED SCENARIO DETECTED...\nAttacker made up an elaborate story to trick someone into giving up info.",
                "question": "What technique uses a fake scenario to manipulate someone?",
                "options": ["A) Impersonation", "B) Pretexting", "C) Baiting", "D) Quid pro quo"],
                "correct": "B",
                "explanation": "Pretexting is making up a fake scenario. Like pretending to be IT support to get passwords."
            },
            {
                "scenario": "INFECTED USB DRIVE FOUND...\nLabeled 'Executive Salaries 2024' and left in the parking lot.",
                "question": "What attack leaves infected media for people to find?",
                "options": ["A) Tailgating", "B) Shoulder surfing", "C) Baiting", "D) Pharming"],
                "correct": "C",
                "explanation": "Baiting uses physical media like USB drives with tempting labels. Curiosity kills the cat."
            }
        ]
    },
    {
        "id": 5,
        "day": 5,
        "title": "CRYPTOGRAPHY_OPERATIONS",
        "domain": "Cryptography",
        "brief": "Secure comms channel got compromised. Set up proper crypto and understand how encryption actually works.",
        "questions": [
            {
                "scenario": "ENCRYPTION KEY ANALYSIS...\nSame key being used for both encryption and decryption.",
                "question": "What encryption uses the same key for both?",
                "options": ["A) Asymmetric", "B) Symmetric", "C) Hashing", "D) Steganography"],
                "correct": "B",
                "explanation": "Symmetric encryption uses one key for everything (AES, DES, 3DES). Fast but key distribution sucks."
            },
            {
                "scenario": "PUBLIC KEY INFRASTRUCTURE AUDIT...\nTwo related keys detected. One public, one private.",
                "question": "What encryption uses a public and private key pair?",
                "options": ["A) Symmetric", "B) Asymmetric", "C) Hashing", "D) Stream cipher"],
                "correct": "B",
                "explanation": "Asymmetric uses key pairs (RSA, ECC). Public key encrypts, private key decrypts. Fixes key distribution but slower."
            },
            {
                "scenario": "PASSWORD HASH CRACKING ATTEMPT...\nOne-way function detected. Can't reverse it to get the original password.",
                "question": "What cryptographic function is one-way?",
                "options": ["A) Encryption", "B) Encoding", "C) Hashing", "D) Obfuscation"],
                "correct": "C",
                "explanation": "Hashing (MD5, SHA-256) is one-way. Used for storing passwords and checking integrity."
            },
            {
                "scenario": "CERTIFICATE VALIDATION IN PROGRESS...\nVerifying digital signature on this software download.",
                "question": "What provides authentication and integrity for digital documents?",
                "options": ["A) Encryption", "B) Digital signature", "C) Hashing", "D) Steganography"],
                "correct": "B",
                "explanation": "Digital signatures use asymmetric crypto to prove who made it and that it hasn't changed."
            },
            {
                "scenario": "WIRELESS ENCRYPTION PROTOCOL...\nChecking WPA2's encryption algorithm for vulnerabilities.",
                "question": "What encryption does WPA2 use?",
                "options": ["A) DES", "B) 3DES", "C) AES", "D) RC4"],
                "correct": "C",
                "explanation": "WPA2 uses AES - the government standard. WEP used RC4 which is broken. WPA3 also uses AES."
            }
        ]
    },
    {
        "id": 6,
        "day": 6,
        "title": "PKI_INFRASTRUCTURE_BREACH",
        "domain": "Cryptography",
        "brief": "Certificate authority got compromised. Learn PKI and certificate management to fix the trust chain.",
        "questions": [
            {
                "scenario": "CERTIFICATE REVOCATION CHECK...\nNeed to invalidate this compromised cert immediately.",
                "question": "What checks if a certificate has been revoked?",
                "options": ["A) CRL", "B) CSR", "C) CA", "D) HSM"],
                "correct": "A",
                "explanation": "CRL (Certificate Revocation List) lists revoked certs. OCSP is the newer real-time version."
            },
            {
                "scenario": "CERTIFICATE REQUEST ANALYSIS...\nSomeone requesting a new certificate from the CA.",
                "question": "What's generated when requesting a cert from a CA?",
                "options": ["A) CRL", "B) CSR", "C) PKI", "D) OCSP"],
                "correct": "B",
                "explanation": "CSR (Certificate Signing Request) gets sent to a CA. Contains public key and identity info."
            },
            {
                "scenario": "ROOT CA SECURITY AUDIT...\nChecking out the trust anchor of the whole PKI setup.",
                "question": "What's the top-level CA in a PKI hierarchy?",
                "options": ["A) Intermediate CA", "B) Root CA", "C) Registration Authority", "D) Subordinate CA"],
                "correct": "B",
                "explanation": "Root CA is at the top. Kept offline for security. Intermediate CAs do the day-to-day work."
            },
            {
                "scenario": "CERTIFICATE CHAIN VALIDATION...\nVerifying the trust path from end cert to root CA.",
                "question": "What's the path from end certificate to root CA called?",
                "options": ["A) Trust chain", "B) Certificate chain", "C) Key chain", "D) Security chain"],
                "correct": "B",
                "explanation": "Certificate chain links your cert through intermediate CAs to the root. Each level validates the next."
            },
            {
                "scenario": "CERTIFICATE EXPIRATION ALERT...\nCert expired. Service is about to go down.",
                "question": "What happens when a cert expires?",
                "options": ["A) It auto-renews", "B) It becomes untrusted", "C) It gets revoked", "D) Nothing happens"],
                "correct": "B",
                "explanation": "Expired certs become untrusted. Browsers reject them. Renew before it expires."
            }
        ]
    },
    {
        "id": 7,
        "day": 7,
        "title": "IDENTITY_AND_ACCESS_CONTROL",
        "domain": "Identity and Access Management",
        "brief": "Unauthorized access in HR systems. Set up proper authentication and authorization controls.",
        "questions": [
            {
                "scenario": "AUTHENTICATION MECHANISM ANALYSIS...\nUser verified by password, token, and fingerprint.",
                "question": "What's authentication using three different factor types?",
                "options": ["A) Two-factor authentication", "B) Multi-factor authentication", "C) Single sign-on", "D) Biometric authentication"],
                "correct": "B",
                "explanation": "MFA uses multiple factor types: something you know (password), have (token), are (biometric)."
            },
            {
                "scenario": "BIOMETRIC SYSTEM CALIBRATION...\nAdjusting sensitivity between false positives and false negatives.",
                "question": "When a biometric system incorrectly accepts an unauthorized user?",
                "options": ["A) False negative", "B) False positive", "C) Type I error", "D) CER"],
                "correct": "B",
                "explanation": "False positive accepts wrong people. False negative rejects right people. CER is where they meet."
            },
            {
                "scenario": "AUTHENTICATION PROTOCOL SELECTION...\nNeed to support multiple services with one login.",
                "question": "What lets users authenticate once for multiple systems?",
                "options": ["A) Multi-factor authentication", "B) Single sign-on", "C) Federation", "D) RADIUS"],
                "correct": "B",
                "explanation": "SSO lets you log in once for everything. Examples: Kerberos, SAML, OAuth."
            },
            {
                "scenario": "FEDERATED IDENTITY INVESTIGATION...\nExternal users accessing our internal stuff.",
                "question": "What lets users from one org access another org's resources?",
                "options": ["A) SSO", "B) MFA", "C) Federation", "D) LDAP"],
                "correct": "C",
                "explanation": "Federation lets users keep their own credentials while accessing partner stuff. SAML is common."
            },
            {
                "scenario": "LEAST PRIVILEGE VIOLATION DETECTED...\nUser has admin rights but only needs to read.",
                "question": "What principle says users get minimum permissions needed?",
                "options": ["A) Separation of duties", "B) Least privilege", "C) Need to know", "D) Defense in depth"],
                "correct": "B",
                "explanation": "Least privilege means giving people only what they need. Limits damage from compromised accounts."
            }
        ]
    },
    {
        "id": 8,
        "day": 8,
        "title": "FIREWALL_CONFIGURATION_AUDIT",
        "domain": "Network Security",
        "brief": "Perimeter defenses have gaps. Review firewall rules and set up proper network segmentation.",
        "questions": [
            {
                "scenario": "PACKET FILTERING ANALYSIS...\nFirewall only looking at IP addresses and ports.",
                "question": "What firewall only checks packet headers (Layer 3 and 4)?",
                "options": ["A) Stateful", "B) Stateless", "C) Application-layer", "D) Next-gen"],
                "correct": "B",
                "explanation": "Stateless firewalls just check headers. Fast but dumb. Stateful tracks connections."
            },
            {
                "scenario": "CONNECTION STATE TABLE REVIEW...\nFirewall tracking all active connections and their states.",
                "question": "What firewall tracks connection state?",
                "options": ["A) Stateless", "B) Stateful", "C) Packet filtering", "D) Circuit-level"],
                "correct": "B",
                "explanation": "Stateful firewalls keep state tables. They understand TCP handshakes and make smarter decisions."
            },
            {
                "scenario": "NETWORK SEGMENTATION DESIGN...\nIsolating public web servers from internal network.",
                "question": "What network zone is for public servers between internal and external?",
                "options": ["A) DMZ", "B) VLAN", "C) VPN", "D) Intranet"],
                "correct": "A",
                "explanation": "DMZ is the buffer zone for public servers. Sits between internet and internal network."
            },
            {
                "scenario": "IMPLICIT DENY RULE VERIFICATION...\nChecking firewall's default behavior.",
                "question": "What principle blocks all traffic not explicitly allowed?",
                "options": ["A) Explicit allow", "B) Implicit deny", "C) Default permit", "D) Whitelist only"],
                "correct": "B",
                "explanation": "Implicit deny blocks everything by default. Only let through what you explicitly allow."
            },
            {
                "scenario": "ACL RULE ORDER AUDIT...\nRules get processed in order. First match wins.",
                "question": "What happens when a packet matches a firewall rule?",
                "options": ["A) Checks all rules", "B) Stops processing", "C) Continues to next rule", "D) Generates alert"],
                "correct": "B",
                "explanation": "First match wins. Firewall stops when it finds a match. Put specific rules at the top."
            }
        ]
    },
    {
        "id": 9,
        "day": 9,
        "title": "NETWORK_ARCHITECTURE_DESIGN",
        "domain": "Architecture and Design",
        "brief": "Designing secure network for new office. Set up proper segmentation and security zones.",
        "questions": [
            {
                "scenario": "VLAN SEGMENTATION PLANNING...\nIsolating departments logically on same physical network.",
                "question": "What creates logical network segments on a physical switch?",
                "options": ["A) Subnetting", "B) VLAN", "C) VPN", "D) NAT"],
                "correct": "B",
                "explanation": "VLANs make logical segments on the same hardware. Better security and less broadcast traffic."
            },
            {
                "scenario": "DEFENSE IN DEPTH STRATEGY...\nMultiple overlapping security layers.",
                "question": "What security approach uses multiple layers?",
                "options": ["A) Defense in depth", "B) Least privilege", "C) Zero trust", "D) Air gap"],
                "correct": "A",
                "explanation": "Defense in depth means layered security. If one fails, others still protect."
            },
            {
                "scenario": "NETWORK ADDRESS TRANSLATION...\nHiding internal IPs from external networks.",
                "question": "What lets multiple internal devices share one public IP?",
                "options": ["A) VPN", "B) Proxy", "C) NAT", "D) VLAN"],
                "correct": "C",
                "explanation": "NAT translates internal IPs to public IPs. Hides internal structure and saves IPv4 addresses."
            },
            {
                "scenario": "ZERO TRUST ARCHITECTURE IMPLEMENTATION...\nNever trust, always verify.",
                "question": "What security model assumes no implicit trust?",
                "options": ["A) Defense in depth", "B) Zero trust", "C) Least privilege", "D) Air gap"],
                "correct": "B",
                "explanation": "Zero trust assumes everything's already compromised. Verify everything always."
            },
            {
                "scenario": "SECURE PROTOCOL IMPLEMENTATION...\nReplacing insecure protocols.",
                "question": "What's the secure alternative to HTTP?",
                "options": ["A) SFTP", "B) SSH", "C) HTTPS", "D) TLS"],
                "correct": "C",
                "explanation": "HTTPS is HTTP over TLS/SSL (port 443). Always use it for sensitive data."
            }
        ]
    },
    {
        "id": 10,
        "day": 10,
        "title": "CLOUD_SECURITY_ASSESSMENT",
        "domain": "Architecture and Design",
        "brief": "Company moving to cloud. Learn cloud models and set up proper security.",
        "questions": [
            {
                "scenario": "CLOUD SERVICE MODEL ANALYSIS...\nVendor provides infrastructure. We manage everything above hardware.",
                "question": "What cloud model provides virtualized computing resources?",
                "options": ["A) SaaS", "B) PaaS", "C) IaaS", "D) DaaS"],
                "correct": "C",
                "explanation": "IaaS gives you VMs, storage, networks. Examples: AWS EC2, Azure VMs. You manage OS and up."
            },
            {
                "scenario": "SHARED RESPONSIBILITY MODEL...\nDefining security boundaries.",
                "question": "In IaaS, who patches the OS?",
                "options": ["A) Cloud provider", "B) Customer", "C) Both equally", "D) Third-party vendor"],
                "correct": "B",
                "explanation": "In IaaS, you manage OS and up. Provider handles physical hardware and hypervisor."
            },
            {
                "scenario": "CLOUD DEPLOYMENT MODEL SELECTION...\nNeed dedicated infrastructure for compliance.",
                "question": "What cloud deployment is dedicated to one org?",
                "options": ["A) Public", "B) Private", "C) Community", "D) Hybrid"],
                "correct": "B",
                "explanation": "Private cloud is just for you. More control but more expensive. Public is shared."
            },
            {
                "scenario": "CLOUD STORAGE ENCRYPTION...\nData encrypted before uploading.",
                "question": "What's it called when you encrypt data before sending to cloud?",
                "options": ["A) Encryption at rest", "B) Encryption in transit", "C) Client-side encryption", "D) Server-side encryption"],
                "correct": "C",
                "explanation": "Client-side encryption means the provider never sees your unencrypted data."
            },
            {
                "scenario": "CLOUD ACCESS SECURITY BROKER DEPLOYMENT...\nMonitoring and enforcing policies for cloud services.",
                "question": "What sits between users and cloud services to enforce policies?",
                "options": ["A) Firewall", "B) CASB", "C) IDS", "D) VPN"],
                "correct": "B",
                "explanation": "CASB enforces security policies for cloud services. Gives visibility and control."
            }
        ]
    },
    {
        "id": 11,
        "day": 11,
        "title": "VIRTUALIZATION_SECURITY",
        "domain": "Architecture and Design",
        "brief": "Virtual environment showing signs of VM escape attempts. Secure the virtualization setup.",
        "questions": [
            {
                "scenario": "HYPERVISOR VULNERABILITY SCAN...\nSoftware layer that creates VMs is under attack.",
                "question": "What software creates and manages VMs?",
                "options": ["A) Container", "B) Hypervisor", "C) Virtual switch", "D) OS"],
                "correct": "B",
                "explanation": "Hypervisor (VMM) creates and manages VMs. Type 1 runs on hardware, Type 2 runs on OS."
            },
            {
                "scenario": "VM ESCAPE DETECTED...\nMalware broke out of the VM to attack the host.",
                "question": "What attack breaks out of a VM to access the host?",
                "options": ["A) Privilege escalation", "B) VM escape", "C) Container breakout", "D) Hypervisor exploit"],
                "correct": "B",
                "explanation": "VM escape breaks VM isolation to attack the host or other VMs. Rare but bad. Keep hypervisors patched."
            },
            {
                "scenario": "SNAPSHOT MANAGEMENT AUDIT...\nPoint-in-time VM copies creating storage and security issues.",
                "question": "What VM feature captures state at a specific time?",
                "options": ["A) Clone", "B) Template", "C) Snapshot", "D) Backup"],
                "correct": "C",
                "explanation": "Snapshots capture VM state. Good for backups but can contain sensitive data and eat storage."
            },
            {
                "scenario": "VM SPRAWL INVESTIGATION...\nUncontrolled VM creation causing problems.",
                "question": "What happens when VMs are created without oversight?",
                "options": ["A) VM escape", "B) VM sprawl", "C) Hypervisor overflow", "D) Resource exhaustion"],
                "correct": "B",
                "explanation": "VM sprawl is out-of-control VM creation. Leads to wasted resources and forgotten unpatched VMs."
            },
            {
                "scenario": "CONTAINER SECURITY ASSESSMENT...\nLightweight virtualization sharing the kernel.",
                "question": "What provides OS-level virtualization sharing the host kernel?",
                "options": ["A) Virtual machine", "B) Container", "C) Hypervisor", "D) Emulator"],
                "correct": "B",
                "explanation": "Containers (Docker, Kubernetes) share the host kernel. Lighter than VMs but less isolated."
            }
        ]
    },
    {
        "id": 12,
        "day": 12,
        "title": "MOBILE_DEVICE_SECURITY",
        "domain": "Architecture and Design",
        "brief": "BYOD policy needs implementation. Secure mobile devices accessing company stuff.",
        "questions": [
            {
                "scenario": "MDM DEPLOYMENT PLANNING...\nNeed centralized management of mobile devices.",
                "question": "What allows centralized mobile device management?",
                "options": ["A) VPN", "B) MDM", "C) NAC", "D) CASB"],
                "correct": "B",
                "explanation": "MDM centrally manages mobile devices. Can enforce policies, remote wipe, configure settings."
            },
            {
                "scenario": "CONTAINERIZATION IMPLEMENTATION...\nSeparating work data from personal data on employee devices.",
                "question": "What isolates corporate data from personal data?",
                "options": ["A) Full device encryption", "B) Containerization", "C) Remote wipe", "D) Geofencing"],
                "correct": "B",
                "explanation": "Containerization separates work and personal data on the same device. Can wipe work without touching personal."
            },
            {
                "scenario": "GEOLOCATION POLICY ENFORCEMENT...\nRestricting functionality based on device location.",
                "question": "What MDM feature restricts capabilities based on location?",
                "options": ["A) Containerization", "B) Remote wipe", "C) Geofencing", "D) Push notifications"],
                "correct": "C",
                "explanation": "Geofencing triggers actions based on location. Can disable camera in secure areas, etc."
            },
            {
                "scenario": "JAILBREAK DETECTION...\nDevice has removed manufacturer restrictions.",
                "question": "What's it called when iOS restrictions are removed?",
                "options": ["A) Rooting", "B) Jailbreaking", "C) Sideloading", "D) Unlocking"],
                "correct": "B",
                "explanation": "Jailbreaking (iOS) or rooting (Android) removes restrictions. Allows unauthorized apps but bypasses security."
            },
            {
                "scenario": "LOST DEVICE RESPONSE...\nCompany phone stolen. Need to protect data.",
                "question": "What MDM capability erases all data from a lost device?",
                "options": ["A) Geofencing", "B) Remote lock", "C) Remote wipe", "D) Containerization"],
                "correct": "C",
                "explanation": "Remote wipe erases device data remotely. Full wipe gets everything, selective only removes work data."
            }
        ]
    },
    {
        "id": 13,
        "day": 13,
        "title": "SECURE_CODING_PRACTICES",
        "domain": "Architecture and Design",
        "brief": "Web app vulnerabilities found in production. Find and fix common coding problems.",
        "questions": [
            {
                "scenario": "INPUT VALIDATION BYPASS...\nAttacker injecting SQL through the login form.",
                "question": "What attack inserts malicious SQL into queries?",
                "options": ["A) XSS", "B) CSRF", "C) SQL injection", "D) Buffer overflow"],
                "correct": "C",
                "explanation": "SQL injection puts malicious SQL through user inputs. Stop it with parameterized queries."
            },
            {
                "scenario": "SCRIPT INJECTION DETECTED...\nMalicious JavaScript running in victim's browser from a trusted site.",
                "question": "What attack injects scripts into web pages?",
                "options": ["A) SQL injection", "B) XSS", "C) CSRF", "D) XXE"],
                "correct": "B",
                "explanation": "XSS injects malicious scripts. Stored XSS goes in the database, reflected XSS is in the URL."
            },
            {
                "scenario": "SESSION HIJACKING ATTEMPT...\nAttacker tricking victim into doing stuff while logged in.",
                "question": "What attack tricks authenticated users into unwanted actions?",
                "options": ["A) XSS", "B) CSRF", "C) Session fixation", "D) Clickjacking"],
                "correct": "B",
                "explanation": "CSRF tricks logged-in users into making unwanted requests. Stop it with anti-CSRF tokens."
            },
            {
                "scenario": "MEMORY CORRUPTION EXPLOIT...\nToo much data overwriting memory, potentially running malicious code.",
                "question": "What attack writes data beyond allocated memory?",
                "options": ["A) SQL injection", "B) Buffer overflow", "C) Memory leak", "D) Integer overflow"],
                "correct": "B",
                "explanation": "Buffer overflow writes past buffer boundaries to overwrite memory and execute code."
            },
            {
                "scenario": "CODE REVIEW FINDINGS...\nHardcoded credentials in the source code.",
                "question": "What practice protects sensitive info in code?",
                "options": ["A) Code obfuscation", "B) Secrets management", "C) Version control", "D) Code signing"],
                "correct": "B",
                "explanation": "Secrets management stores credentials externally. Never hardcode passwords or API keys."
            }
        ]
    },
    {
        "id": 14,
        "day": 14,
        "title": "VULNERABILITY_SCANNING",
        "domain": "Security Operations",
        "brief": "Quarterly vulnerability assessment is due. Scan infrastructure and prioritize what to fix.",
        "questions": [
            {
                "scenario": "CREDENTIALED SCAN CONFIGURATION...\nProviding scanner with login credentials for deeper analysis.",
                "question": "What scan type logs into systems for accurate results?",
                "options": ["A) Non-credentialed", "B) Credentialed", "C) External", "D) Passive"],
                "correct": "B",
                "explanation": "Credentialed scans log in to check patch levels accurately. Non-credentialed only sees external stuff."
            },
            {
                "scenario": "CVSS SCORE ANALYSIS...\nPrioritizing vulnerabilities by severity.",
                "question": "What system rates vulnerability severity 0-10?",
                "options": ["A) CVSS", "B) CVE", "C) CPE", "D) CWE"],
                "correct": "A",
                "explanation": "CVSS rates severity 0-10. CVE identifies vulnerabilities, CVSS scores them."
            },
            {
                "scenario": "FALSE POSITIVE INVESTIGATION...\nScanner reporting a vulnerability that doesn't exist.",
                "question": "What's it called when a scanner reports a non-existent vulnerability?",
                "options": ["A) False negative", "B) False positive", "C) True positive", "D) True negative"],
                "correct": "B",
                "explanation": "False positive reports something that's not there. False negative misses real vulnerabilities."
            },
            {
                "scenario": "PATCH MANAGEMENT PRIORITIZATION...\nMissing critical patches on internet-facing servers.",
                "question": "Which vulnerabilities should be patched first?",
                "options": ["A) Lowest CVSS score", "B) Easiest to patch", "C) Highest risk to organization", "D) Oldest vulnerabilities"],
                "correct": "C",
                "explanation": "Prioritize by actual risk: critical severity + internet-facing + active exploits + sensitive data."
            },
            {
                "scenario": "CONTINUOUS MONITORING IMPLEMENTATION...\nReal-time vulnerability detection instead of periodic scanning.",
                "question": "What continuously monitors for new vulnerabilities?",
                "options": ["A) Annual assessment", "B) Continuous monitoring", "C) Penetration testing", "D) Audit"],
                "correct": "B",
                "explanation": "Continuous monitoring detects vulnerabilities in real-time. Better than periodic scans that miss stuff between runs."
            }
        ]
    },
    {
        "id": 15,
        "day": 15,
        "title": "MID_POINT_ASSESSMENT",
        "domain": "Mixed Review",
        "brief": "Halfway through training. Test your knowledge across everything covered so far.",
        "questions": [
            {
                "scenario": "SECURITY INCIDENT TRIAGE...\nMultiple alerts going off. Need to find the biggest threat.",
                "question": "Attacker gained root access to a server. What's this called?",
                "options": ["A) Privilege escalation", "B) Lateral movement", "C) Initial access", "D) Command and control"],
                "correct": "A",
                "explanation": "Privilege escalation means getting higher permissions like root or admin. Critical attack phase."
            },
            {
                "scenario": "SECURITY FRAMEWORK SELECTION...\nPicking standards for the cybersecurity program.",
                "question": "What framework organizes cybersecurity by functions?",
                "options": ["A) ISO 27001", "B) NIST CSF", "C) PCI DSS", "D) COBIT"],
                "correct": "B",
                "explanation": "NIST CSF organizes into: Identify, Protect, Detect, Respond, Recover."
            },
            {
                "scenario": "DATA CLASSIFICATION POLICY...\nLabeling data by sensitivity.",
                "question": "What process categorizes data by sensitivity?",
                "options": ["A) Data loss prevention", "B) Data classification", "C) Data governance", "D) Data masking"],
                "correct": "B",
                "explanation": "Data classification labels data (public, internal, confidential, restricted) to control handling."
            },
            {
                "scenario": "SECURE COMMUNICATIONS...\nSetting up encrypted connection across untrusted network.",
                "question": "What creates encrypted tunnels across untrusted networks?",
                "options": ["A) TLS", "B) IPSec", "C) SSH", "D) All of the above"],
                "correct": "D",
                "explanation": "All create encrypted tunnels. TLS for apps, IPSec for VPNs, SSH for remote access."
            },
            {
                "scenario": "INCIDENT RESPONSE PROCEDURE...\nThreat contained. Now preserving evidence.",
                "question": "What preserves evidence in its original state?",
                "options": ["A) Chain of custody", "B) Legal hold", "C) Evidence preservation", "D) Forensic imaging"],
                "correct": "A",
                "explanation": "Chain of custody documents who handled evidence, when, and why. Critical for court."
            }
        ]
    },
    {
        "id": 16,
        "day": 16,
        "title": "PENETRATION_TESTING",
        "domain": "Security Operations",
        "brief": "Authorized security assessment of corporate systems. Learn pen testing methods and rules.",
        "questions": [
            {
                "scenario": "RULES OF ENGAGEMENT DEFINITION...\nPen test starting with zero info about the target.",
                "question": "What pen test simulates an external attacker with no prior knowledge?",
                "options": ["A) White box", "B) Gray box", "C) Black box", "D) Crystal box"],
                "correct": "C",
                "explanation": "Black box has no prior knowledge. White box has full knowledge. Gray box is partial."
            },
            {
                "scenario": "RECONNAISSANCE PHASE...\nGathering info without directly touching the target.",
                "question": "What's passive information gathering called?",
                "options": ["A) Active recon", "B) Passive recon", "C) Footprinting", "D) Enumeration"],
                "correct": "B",
                "explanation": "Passive recon gathers info without interaction (OSINT, public records). Active recon directly touches the target."
            },
            {
                "scenario": "EXPLOITATION FRAMEWORK...\nUsing a standard tool to exploit vulnerabilities.",
                "question": "What popular framework automates exploitation?",
                "options": ["A) Nmap", "B) Wireshark", "C) Metasploit", "D) Burp Suite"],
                "correct": "C",
                "explanation": "Metasploit is the main exploitation framework with thousands of exploits."
            },
            {
                "scenario": "PIVOT ATTACK STRATEGY...\nUsing compromised system to attack other internal systems.",
                "question": "What uses a compromised system to attack others on the network?",
                "options": ["A) Privilege escalation", "B) Pivoting", "C) Port forwarding", "D) Tunneling"],
                "correct": "B",
                "explanation": "Pivoting (lateral movement) uses compromised systems as stepping stones."
            },
            {
                "scenario": "POST-ENGAGEMENT ACTIVITIES...\nDocumenting findings and giving recommendations.",
                "question": "What documents pen test findings and recommendations?",
                "options": ["A) Rules of engagement", "B) Pen test report", "C) Vulnerability scan", "D) Risk assessment"],
                "correct": "B",
                "explanation": "Pen test report documents methodology, findings, evidence, and how to fix issues."
            }
        ]
    },
    {
        "id": 17,
        "day": 17,
        "title": "INCIDENT_RESPONSE",
        "domain": "Security Operations",
        "brief": "Ransomware outbreak detected. Follow incident response procedures to contain and recover.",
        "questions": [
            {
                "scenario": "INCIDENT RESPONSE LIFECYCLE...\nFormal process for handling security incidents.",
                "question": "What's the correct order of incident response phases?",
                "options": ["A) Contain, Prepare, Detect, Recover", "B) Prepare, Detect, Contain, Eradicate, Recover, Lessons Learned", "C) Detect, Respond, Report, Review", "D) Identify, Protect, Detect, Respond"],
                "correct": "B",
                "explanation": "NIST IR phases: 1) Preparation 2) Detection 3) Containment/Eradication/Recovery 4) Post-Incident."
            },
            {
                "scenario": "CONTAINMENT STRATEGY SELECTION...\nIsolating infected systems while preserving evidence.",
                "question": "What isolates affected systems but keeps them running for analysis?",
                "options": ["A) Shutdown", "B) Removal", "C) Isolation", "D) Eradication"],
                "correct": "C",
                "explanation": "Isolation quarantines systems while preserving evidence. Shutdown loses volatile memory."
            },
            {
                "scenario": "EVIDENCE COLLECTION...\nCapturing volatile data before powering down.",
                "question": "What's the correct order of volatility for evidence?",
                "options": ["A) Hard drive, RAM, logs, network traffic", "B) CPU registers/cache, RAM, hard drive, logs", "C) Logs, hard drive, RAM, network", "D) Network, RAM, hard drive, backups"],
                "correct": "B",
                "explanation": "Order of volatility: CPU/cache, RAM, swap, hard drive, logs, backups. Collect most volatile first."
            },
            {
                "scenario": "LESSONS LEARNED SESSION...\nPost-incident review to improve response.",
                "question": "What phase analyzes incident response to improve future handling?",
                "options": ["A) Preparation", "B) Detection", "C) Containment", "D) Lessons learned"],
                "correct": "D",
                "explanation": "Lessons learned reviews what worked and what failed. Update procedures and improve detection."
            },
            {
                "scenario": "INCIDENT COMMUNICATION...\nFiguring out who needs to know about the security incident.",
                "question": "What defines who to notify during incidents?",
                "options": ["A) BCP", "B) Communication plan", "C) SLA", "D) MOU"],
                "correct": "B",
                "explanation": "Communication plan defines notification procedures: who, what, when, how."
            }
        ]
    },
    {
        "id": 18,
        "day": 18,
        "title": "SECURITY_POLICIES",
        "domain": "Governance and Compliance",
        "brief": "Audit findings need updated security policies. Build a comprehensive policy framework.",
        "questions": [
            {
                "scenario": "POLICY HIERARCHY DEFINITION...\nHigh-level management statement about security.",
                "question": "What provides high-level security direction from management?",
                "options": ["A) Standard", "B) Procedure", "C) Policy", "D) Guideline"],
                "correct": "C",
                "explanation": "Policy is high-level and mandatory. Standards are specific requirements. Procedures are steps."
            },
            {
                "scenario": "ACCEPTABLE USE POLICY ENFORCEMENT...\nDefining appropriate use of company IT.",
                "question": "What defines acceptable use of company tech?",
                "options": ["A) AUP", "B) BCP", "C) NDA", "D) SLA"],
                "correct": "A",
                "explanation": "AUP defines appropriate IT use. Covers email, internet, equipment. Violations can get you fired."
            },
            {
                "scenario": "DATA RETENTION REQUIREMENTS...\nDefining how long to keep different data for legal/business reasons.",
                "question": "What specifies how long to retain different data types?",
                "options": ["A) Data classification", "B) Data retention", "C) Data disposal", "D) Data backup"],
                "correct": "B",
                "explanation": "Data retention policy specifies retention periods based on legal and business requirements."
            },
            {
                "scenario": "CHANGE MANAGEMENT PROCESS...\nControlling changes to production systems.",
                "question": "What ensures changes are reviewed before implementation?",
                "options": ["A) Incident management", "B) Change management", "C) Configuration management", "D) Patch management"],
                "correct": "B",
                "explanation": "Change management controls production changes: request, review, test, approve, implement, document."
            },
            {
                "scenario": "SECURITY AWARENESS TRAINING...\nEducating employees about security threats.",
                "question": "How often should security awareness training happen?",
                "options": ["A) Once at hiring", "B) Annually", "C) Quarterly", "D) Ongoing/continuous"],
                "correct": "D",
                "explanation": "Security awareness should be ongoing: annual training, monthly tips, simulated phishing, role-based training."
            }
        ]
    },
    {
        "id": 19,
        "day": 19,
        "title": "RISK_MANAGEMENT",
        "domain": "Governance and Compliance",
        "brief": "Annual risk assessment is due. Identify, analyze, and prioritize organizational risks.",
        "questions": [
            {
                "scenario": "RISK ASSESSMENT METHODOLOGY...\nEvaluating likelihood and impact of threats.",
                "question": "What's the formula for calculating risk?",
                "options": ["A) Threat x Vulnerability", "B) Impact x Likelihood", "C) Asset x Threat", "D) Vulnerability x Impact"],
                "correct": "B",
                "explanation": "Risk = Impact x Likelihood. Also: Risk = Threat x Vulnerability x Asset Value."
            },
            {
                "scenario": "RISK TREATMENT OPTIONS...\nDeciding how to handle identified risk.",
                "question": "What risk response accepts the risk without mitigation?",
                "options": ["A) Transfer", "B) Avoid", "C) Mitigate", "D) Accept"],
                "correct": "D",
                "explanation": "Risk responses: Accept (do nothing), Avoid (eliminate), Mitigate (reduce), Transfer (insurance)."
            },
            {
                "scenario": "QUANTITATIVE RISK ANALYSIS...\nCalculating annual cost of risk.",
                "question": "What represents expected annual cost of a risk?",
                "options": ["A) SLE", "B) ARO", "C) ALE", "D) TCO"],
                "correct": "C",
                "explanation": "ALE (Annual Loss Expectancy) = SLE (Single Loss Expectancy) x ARO (Annual Rate of Occurrence)."
            },
            {
                "scenario": "RESIDUAL RISK CALCULATION...\nDetermining remaining risk after controls.",
                "question": "What's the risk remaining after implementing controls?",
                "options": ["A) Inherent risk", "B) Residual risk", "C) Total risk", "D) Risk appetite"],
                "correct": "B",
                "explanation": "Residual risk is what's left after controls. Inherent risk is before controls."
            },
            {
                "scenario": "RISK REGISTER MAINTENANCE...\nTracking identified risks over time.",
                "question": "What tracks identified risks and their treatment?",
                "options": ["A) Risk assessment", "B) Risk register", "C) Risk matrix", "D) Risk policy"],
                "correct": "B",
                "explanation": "Risk register tracks risks, likelihood, impact, treatment, owner, status. Updated regularly."
            }
        ]
    },
    {
        "id": 20,
        "day": 20,
        "title": "BUSINESS_CONTINUITY",
        "domain": "Governance and Compliance",
        "brief": "Disaster recovery planning needed. Make sure business can continue during disruptions.",
        "questions": [
            {
                "scenario": "BUSINESS IMPACT ANALYSIS...\nIdentifying critical business functions and dependencies.",
                "question": "What identifies critical functions and recovery requirements?",
                "options": ["A) Risk assessment", "B) Vulnerability assessment", "C) BIA", "D) Audit"],
                "correct": "C",
                "explanation": "BIA identifies critical functions, dependencies, and recovery requirements. Determines MTD, RTO, RPO."
            },
            {
                "scenario": "RECOVERY TIME OBJECTIVE...\nDefining acceptable downtime for critical system.",
                "question": "What defines maximum acceptable downtime?",
                "options": ["A) RTO", "B) RPO", "C) MTD", "D) MTBF"],
                "correct": "A",
                "explanation": "RTO is max acceptable downtime. RPO is max acceptable data loss. MTD is absolute max."
            },
            {
                "scenario": "BACKUP STRATEGY DESIGN...\nDefining acceptable data loss for critical systems.",
                "question": "What defines maximum acceptable data loss?",
                "options": ["A) RTO", "B) RPO", "C) MTD", "D) SLA"],
                "correct": "B",
                "explanation": "RPO is max acceptable data loss in time. RPO = 1 hour means you can lose up to 1 hour of data."
            },
            {
                "scenario": "ALTERNATE SITE SELECTION...\nChoosing backup facility for disaster recovery.",
                "question": "What backup site is fully equipped and ready immediately?",
                "options": ["A) Cold site", "B) Warm site", "C) Hot site", "D) Mobile site"],
                "correct": "C",
                "explanation": "Hot site is fully equipped (minutes/hours). Warm site needs data (days). Cold site is empty (weeks)."
            },
            {
                "scenario": "DISASTER RECOVERY TESTING...\nValidating DR plan without disrupting operations.",
                "question": "What DR test reviews procedures without actually performing them?",
                "options": ["A) Full interruption", "B) Parallel", "C) Simulation", "D) Tabletop"],
                "correct": "D",
                "explanation": "Tabletop discusses scenarios. Simulation tests with fake scenario. Full interruption actually fails over."
            }
        ]
    },
    {
        "id": 21,
        "day": 21,
        "title": "DIGITAL_FORENSICS",
        "domain": "Security Operations",
        "brief": "Insider threat investigation. Properly collect and analyze digital evidence.",
        "questions": [
            {
                "scenario": "FORENSIC IMAGE ACQUISITION...\nCreating exact copy of storage device.",
                "question": "What creates a bit-by-bit copy of storage?",
                "options": ["A) Backup", "B) Clone", "C) Forensic image", "D) Snapshot"],
                "correct": "C",
                "explanation": "Forensic image captures everything including deleted files and slack space. Never work on originals."
            },
            {
                "scenario": "EVIDENCE INTEGRITY VERIFICATION...\nProving evidence hasn't been altered.",
                "question": "What creates a unique fingerprint to verify evidence integrity?",
                "options": ["A) Encryption", "B) Hashing", "C) Compression", "D) Encoding"],
                "correct": "B",
                "explanation": "Cryptographic hashing (MD5, SHA-256) creates a unique fingerprint. Any change = different hash."
            },
            {
                "scenario": "LEGAL EVIDENCE REQUIREMENTS...\nEnsuring evidence is admissible in court.",
                "question": "What requires evidence to be collected and handled properly?",
                "options": ["A) Due diligence", "B) Due care", "C) Chain of custody", "D) Legal hold"],
                "correct": "C",
                "explanation": "Chain of custody documents everyone who handled evidence, when, and why. Gaps break admissibility."
            },
            {
                "scenario": "DATA RECOVERY OPERATIONS...\nRetrieving deleted files from suspect's hard drive.",
                "question": "What file system area often contains recoverable deleted data?",
                "options": ["A) Master boot record", "B) File allocation table", "C) Slack space", "D) Boot sector"],
                "correct": "C",
                "explanation": "Slack space is unused space in clusters. Often has remnants of deleted files."
            },
            {
                "scenario": "E-DISCOVERY PROCESS...\nIdentifying and preserving electronic evidence for legal stuff.",
                "question": "What requires preserving electronic evidence when litigation is anticipated?",
                "options": ["A) Chain of custody", "B) Legal hold", "C) Forensic imaging", "D) Evidence collection"],
                "correct": "B",
                "explanation": "Legal hold suspends normal data destruction when litigation is coming. Must preserve all relevant data."
            }
        ]
    },
    {
        "id": 22,
        "day": 22,
        "title": "SECURITY_MONITORING",
        "domain": "Security Operations",
        "brief": "SOC operations review. Set up effective security monitoring and alerting.",
        "questions": [
            {
                "scenario": "SIEM DEPLOYMENT...\nCentralizing log collection and analysis.",
                "question": "What aggregates logs from multiple sources for correlation?",
                "options": ["A) IDS", "B) SIEM", "C) Firewall", "D) DLP"],
                "correct": "B",
                "explanation": "SIEM aggregates logs, correlates events, generates alerts. Central hub of security operations."
            },
            {
                "scenario": "INTRUSION DETECTION SYSTEM...\nMonitoring network traffic for suspicious stuff.",
                "question": "What security control detects but doesn't prevent attacks?",
                "options": ["A) Firewall", "B) IDS", "C) IPS", "D) WAF"],
                "correct": "B",
                "explanation": "IDS detects and alerts. IPS detects and prevents. IDS is passive, IPS is inline."
            },
            {
                "scenario": "DETECTION METHOD ANALYSIS...\nIdentifying known attack patterns in traffic.",
                "question": "What IDS detection method uses databases of known attacks?",
                "options": ["A) Anomaly-based", "B) Behavior-based", "C) Signature-based", "D) Heuristic"],
                "correct": "C",
                "explanation": "Signature-based detects known attacks. Fast with few false positives but can't detect new stuff."
            },
            {
                "scenario": "LOG RETENTION POLICY...\nFiguring out how long to store security logs.",
                "question": "What's a common log retention period for compliance?",
                "options": ["A) 30 days", "B) 90 days", "C) 1 year", "D) 7 years"],
                "correct": "B",
                "explanation": "90 days is common minimum. Some regulations want longer (PCI DSS = 1 year)."
            },
            {
                "scenario": "SECURITY ORCHESTRATION...\nAutomating response to common alerts.",
                "question": "What automates security operations and incident response?",
                "options": ["A) SIEM", "B) SOAR", "C) IDS", "D) DLP"],
                "correct": "B",
                "explanation": "SOAR automates playbooks and response actions. Integrates with SIEM, IDS, firewalls, etc."
            }
        ]
    },
    {
        "id": 23,
        "day": 23,
        "title": "PHYSICAL_SECURITY",
        "domain": "Architecture and Design",
        "brief": "Physical security assessment of data center. Set up defense-in-depth for physical access.",
        "questions": [
            {
                "scenario": "ACCESS CONTROL IMPLEMENTATION...\nPreventing unauthorized entry while allowing legit access.",
                "question": "What prevents tailgating by allowing only one person through?",
                "options": ["A) Bollard", "B) Mantrap", "C) Turnstile", "D) Badge reader"],
                "correct": "B",
                "explanation": "Mantrap has two doors. First must close before second opens. Stops tailgating."
            },
            {
                "scenario": "PERIMETER SECURITY...\nCreating layered physical defenses around facility.",
                "question": "What's the outermost layer of physical security?",
                "options": ["A) Mantrap", "B) Bollards", "C) Perimeter", "D) Reception"],
                "correct": "C",
                "explanation": "Perimeter is outermost boundary (fences, walls, gates). Multiple layers delay attackers."
            },
            {
                "scenario": "VIDEO SURVEILLANCE SYSTEM...\nRecording activity in and around secure facilities.",
                "question": "What type of control is a security camera?",
                "options": ["A) Preventive", "B) Detective", "C) Corrective", "D) Deterrent"],
                "correct": "B",
                "explanation": "Cameras are detective (detect incidents after). Also deterrent (discourage attempts)."
            },
            {
                "scenario": "ENVIRONMENTAL CONTROLS...\nProtecting equipment from environmental threats.",
                "question": "What protects against short-term power outages?",
                "options": ["A) Generator", "B) UPS", "C) Surge protector", "D) Redundant power"],
                "correct": "B",
                "explanation": "UPS provides battery backup for minutes/hours. Generator provides long-term backup."
            },
            {
                "scenario": "FIRE SUPPRESSION SYSTEM...\nProtecting data center from fire.",
                "question": "What fire suppression is safe for electronics and doesn't use water?",
                "options": ["A) Sprinkler", "B) Dry pipe", "C) Clean agent", "D) Wet pipe"],
                "correct": "C",
                "explanation": "Clean agent systems (FM-200, Inergen) don't harm electronics or people. Water kills equipment."
            }
        ]
    },
    {
        "id": 24,
        "day": 24,
        "title": "APPLICATION_SECURITY",
        "domain": "Architecture and Design",
        "brief": "Secure SDLC implementation needed. Integrate security throughout development lifecycle.",
        "questions": [
            {
                "scenario": "SDLC INTEGRATION...\nBuilding security into software development from the start.",
                "question": "What development approach integrates security throughout SDLC?",
                "options": ["A) Waterfall", "B) Agile", "C) DevSecOps", "D) Rapid prototyping"],
                "correct": "C",
                "explanation": "DevSecOps integrates security into DevOps. Security is everyone's job, not just at the end."
            },
            {
                "scenario": "CODE QUALITY ANALYSIS...\nAutomated scanning of source code for vulnerabilities.",
                "question": "What testing analyzes source code without executing it?",
                "options": ["A) DAST", "B) SAST", "C) Penetration testing", "D) Fuzzing"],
                "correct": "B",
                "explanation": "SAST analyzes source code. DAST tests running application. SAST finds issues early."
            },
            {
                "scenario": "INPUT VALIDATION IMPLEMENTATION...\nPreventing injection attacks through proper data handling.",
                "question": "What secure coding technique prevents injection attacks?",
                "options": ["A) Output encoding", "B) Parameterized queries", "C) Session management", "D) Error handling"],
                "correct": "B",
                "explanation": "Parameterized queries separate code from data. Stops SQL injection."
            },
            {
                "scenario": "API SECURITY IMPLEMENTATION...\nSecuring application programming interfaces.",
                "question": "What should APIs use to authenticate and authorize requests?",
                "options": ["A) Session cookies", "B) API keys", "C) OAuth tokens", "D) All of the above"],
                "correct": "D",
                "explanation": "APIs can use API keys (simple), OAuth/JWT tokens (standard), or other methods depending on needs."
            },
            {
                "scenario": "CODE SIGNING CERTIFICATE...\nProving authenticity and integrity of software.",
                "question": "What proves software hasn't been modified since the developer signed it?",
                "options": ["A) Hash", "B) Encryption", "C) Code signing", "D) Obfuscation"],
                "correct": "C",
                "explanation": "Code signing uses digital certificates to sign executables. Proves who made it and it's not modified."
            }
        ]
    },
    {
        "id": 25,
        "day": 25,
        "title": "SECURE_PROTOCOLS",
        "domain": "Implementation",
        "brief": "Protocol security review across enterprise. Replace insecure protocols with secure alternatives.",
        "questions": [
            {
                "scenario": "SECURE SHELL IMPLEMENTATION...\nReplacing Telnet with encrypted remote access.",
                "question": "What protocol provides secure encrypted remote access?",
                "options": ["A) Telnet", "B) SSH", "C) RDP", "D) VNC"],
                "correct": "B",
                "explanation": "SSH encrypts remote access on port 22. Replaces insecure Telnet (port 23)."
            },
            {
                "scenario": "EMAIL SECURITY PROTOCOLS...\nImplementing encryption for email transmission.",
                "question": "What protocol encrypts email in transit between mail servers?",
                "options": ["A) SMTP", "B) SMTPS", "C) STARTTLS", "D) POP3S"],
                "correct": "C",
                "explanation": "STARTTLS upgrades plain connection to encrypted. SMTPS (port 465) is SMTP over TLS."
            },
            {
                "scenario": "FILE TRANSFER SECURITY...\nReplacing FTP with secure alternative.",
                "question": "What secure protocol should replace FTP?",
                "options": ["A) TFTP", "B) SFTP", "C) FTPS", "D) Both B and C"],
                "correct": "D",
                "explanation": "SFTP uses SSH. FTPS uses TLS. Both are secure FTP replacements. TFTP is worse than FTP."
            },
            {
                "scenario": "TIME SYNCHRONIZATION...\nSecuring network time protocol.",
                "question": "What protocol synchronizes time across network devices?",
                "options": ["A) NTP", "B) SNMP", "C) DNS", "D) DHCP"],
                "correct": "A",
                "explanation": "NTP synchronizes clocks. Critical for logging, certificates, Kerberos."
            },
            {
                "scenario": "SECURE DNS IMPLEMENTATION...\nPreventing DNS spoofing and cache poisoning.",
                "question": "What security extension adds authentication to DNS?",
                "options": ["A) DNS over HTTPS", "B) DNS over TLS", "C) DNSSEC", "D) All of the above"],
                "correct": "C",
                "explanation": "DNSSEC signs DNS records to prevent spoofing. DNS over HTTPS/TLS encrypts queries."
            }
        ]
    },
    {
        "id": 26,
        "day": 26,
        "title": "PRACTICE_EXAM_1",
        "domain": "Mixed Review",
        "brief": "First full-length practice exam. Test knowledge across all domains under exam conditions.",
        "questions": [
            {
                "scenario": "EXAM QUESTION 1...\nCompany needs to ensure deleted data can't be recovered from old hard drives.",
                "question": "What's the most secure method of sanitizing hard drives?",
                "options": ["A) Reformatting", "B) Degaussing", "C) Physical destruction", "D) Overwriting 7 times"],
                "correct": "C",
                "explanation": "Physical destruction (shredding, incineration) is most secure. Degaussing works for magnetic media."
            },
            {
                "scenario": "EXAM QUESTION 2...\nUsers reporting slow network and strange pop-ups. Multiple machines infected.",
                "question": "What should be the FIRST step in incident response?",
                "options": ["A) Eradicate malware", "B) Identify affected systems", "C) Contain the spread", "D) Perform root cause analysis"],
                "correct": "B",
                "explanation": "Follow IR phases: Detection/Identification first. Must identify scope before containment."
            },
            {
                "scenario": "EXAM QUESTION 3...\nApplication lets users upload files which are then shown to other users.",
                "question": "What vulnerability is most likely present?",
                "options": ["A) SQL injection", "B) CSRF", "C) XSS", "D) Buffer overflow"],
                "correct": "C",
                "explanation": "File upload with display to others = stored XSS risk. Attacker uploads malicious script."
            },
            {
                "scenario": "EXAM QUESTION 4...\nOrganization needs to prove they're meeting security requirements to customers.",
                "question": "What type of audit report provides this assurance?",
                "options": ["A) Vulnerability scan", "B) Penetration test", "C) SOC 2", "D) Risk assessment"],
                "correct": "C",
                "explanation": "SOC 2 reports demonstrate compliance. Type I = point in time, Type II = over period."
            },
            {
                "scenario": "EXAM QUESTION 5...\nSSL certificate expired on production web server. Users getting browser warnings.",
                "question": "What's the BEST immediate action?",
                "options": ["A) Disable SSL", "B) Renew and install certificate", "C) Ignore warnings", "D) Use self-signed certificate"],
                "correct": "B",
                "explanation": "Renew certificate immediately. Never disable SSL or use self-signed in production."
            }
        ]
    },
    {
        "id": 27,
        "day": 27,
        "title": "PRACTICE_EXAM_2",
        "domain": "Mixed Review",
        "brief": "Second practice exam. Identify weak areas and reinforce knowledge.",
        "questions": [
            {
                "scenario": "EXAM QUESTION 1...\nEmployee laptop stolen from car. Contains customer data.",
                "question": "What control would have BEST prevented data exposure?",
                "options": ["A) GPS tracking", "B) Full disk encryption", "C) Strong password", "D) Remote wipe"],
                "correct": "B",
                "explanation": "Full disk encryption protects data if device is stolen. Remote wipe needs connection first."
            },
            {
                "scenario": "EXAM QUESTION 2...\nWeb application needs to prevent automated bot attacks.",
                "question": "What technology distinguishes humans from bots?",
                "options": ["A) Firewall", "B) IDS", "C) CAPTCHA", "D) WAF"],
                "correct": "C",
                "explanation": "CAPTCHA challenges users to prove they're human. reCAPTCHA is common."
            },
            {
                "scenario": "EXAM QUESTION 3...\nDatabase admin needs production access but shouldn't see sensitive data.",
                "question": "What technique hides sensitive data while preserving usability?",
                "options": ["A) Encryption", "B) Hashing", "C) Data masking", "D) Tokenization"],
                "correct": "C",
                "explanation": "Data masking replaces sensitive data with realistic but fake data. DBA can work without seeing real stuff."
            },
            {
                "scenario": "EXAM QUESTION 4...\nCompany wants to test employee security awareness.",
                "question": "What should security team conduct?",
                "options": ["A) Vulnerability scan", "B) Penetration test", "C) Simulated phishing", "D) Security audit"],
                "correct": "C",
                "explanation": "Simulated phishing tests employee susceptibility. Track click rates and credential submission."
            },
            {
                "scenario": "EXAM QUESTION 5...\nVPN concentrator at capacity. Users experiencing slow connections.",
                "question": "What solution provides better scalability for remote access?",
                "options": ["A) Add VPN capacity", "B) Implement split tunneling", "C) Deploy ZTNA", "D) Use RDP instead"],
                "correct": "C",
                "explanation": "ZTNA is more scalable than VPN. Users connect directly to applications, not entire network."
            }
        ]
    },
    {
        "id": 28,
        "day": 28,
        "title": "PRACTICE_EXAM_3",
        "domain": "Mixed Review",
        "brief": "Third practice exam. Final preparation before certification exam.",
        "questions": [
            {
                "scenario": "EXAM QUESTION 1...\nAuditor found systems using TLS 1.0.",
                "question": "What's the recommended action?",
                "options": ["A) Nothing, TLS 1.0 is fine", "B) Upgrade to TLS 1.2 or higher", "C) Switch to SSL 3.0", "D) Disable encryption"],
                "correct": "B",
                "explanation": "TLS 1.0 and 1.1 are deprecated. Use TLS 1.2 minimum, preferably TLS 1.3."
            },
            {
                "scenario": "EXAM QUESTION 2...\nUsers clicking malicious links despite training.",
                "question": "What additional technical control should be implemented?",
                "options": ["A) Email encryption", "B) URL filtering", "C) SPF records", "D) DMARC"],
                "correct": "B",
                "explanation": "URL filtering blocks known malicious sites. Combine technical controls with training."
            },
            {
                "scenario": "EXAM QUESTION 3...\nDevelopers need production access for troubleshooting but shouldn't see real customer data.",
                "question": "What environment should they use?",
                "options": ["A) Production", "B) Development", "C) Staging with masked data", "D) Test"],
                "correct": "C",
                "explanation": "Staging mirrors production but with masked data. Developers can troubleshoot without seeing real data."
            },
            {
                "scenario": "EXAM QUESTION 4...\nOrganization wants to detect insider threats.",
                "question": "What technology monitors user behavior for anomalies?",
                "options": ["A) IDS", "B) DLP", "C) UEBA", "D) SIEM"],
                "correct": "C",
                "explanation": "UEBA establishes baselines and detects anomalies. Identifies insider threats and compromised accounts."
            },
            {
                "scenario": "EXAM QUESTION 5...\nCloud application needs to verify user identity across multiple services.",
                "question": "What standard is best for cloud SSO and federation?",
                "options": ["A) Kerberos", "B) RADIUS", "C) SAML", "D) TACACS+"],
                "correct": "C",
                "explanation": "SAML is standard for cloud SSO and federation. OAuth is for authorization."
            }
        ]
    },
    {
        "id": 29,
        "day": 29,
        "title": "FINAL_REVIEW_SESSION",
        "domain": "Mixed Review",
        "brief": "Last chance to identify gaps. Review commonly missed topics.",
        "questions": [
            {
                "scenario": "REVIEW QUESTION 1...\nCommon exam trap: authentication vs authorization.",
                "question": "User proves identity with username/password. What is this?",
                "options": ["A) Authorization", "B) Authentication", "C) Accounting", "D) Access control"],
                "correct": "B",
                "explanation": "Authentication proves who you are. Authorization grants permissions. Accounting tracks what you did."
            },
            {
                "scenario": "REVIEW QUESTION 2...\nCommon confusion: hashing vs encryption.",
                "question": "What's a one-way cryptographic function that can't be reversed?",
                "options": ["A) Encryption", "B) Encoding", "C) Hashing", "D) Obfuscation"],
                "correct": "C",
                "explanation": "Hashing is one-way (MD5, SHA-256). Encryption is two-way (AES, RSA). Hash passwords, encrypt data."
            },
            {
                "scenario": "REVIEW QUESTION 3...\nFrequently tested: preventive vs detective controls.",
                "question": "What type of control is a firewall?",
                "options": ["A) Preventive", "B) Detective", "C) Corrective", "D) Deterrent"],
                "correct": "A",
                "explanation": "Preventive stops incidents (firewalls, encryption). Detective finds incidents (IDS, cameras)."
            },
            {
                "scenario": "REVIEW QUESTION 4...\nCommon mistake: identifying attack types.",
                "question": "Attacker intercepts and modifies communications between two parties. What is this?",
                "options": ["A) Replay attack", "B) Man-in-the-middle", "C) Session hijacking", "D) Eavesdropping"],
                "correct": "B",
                "explanation": "MITM intercepts and can modify. Eavesdropping just listens. Session hijacking steals existing session."
            },
            {
                "scenario": "REVIEW QUESTION 5...\nFrequently confused: public vs private cloud.",
                "question": "What cloud model shares infrastructure among multiple organizations?",
                "options": ["A) Private", "B) Public", "C) Community", "D) Hybrid"],
                "correct": "B",
                "explanation": "Public cloud is multi-tenant (AWS, Azure, GCP). Private is dedicated. Community is shared by a specific group."
            }
        ]
    },
    {
        "id": 30,
        "day": 30,
        "title": "FINAL_EXAM_SIMULATION",
        "domain": "Mixed Review",
        "brief": "Final full-length exam before certification. Demonstrate readiness to pass Security+.",
        "questions": [
            {
                "scenario": "FINAL EXAM Q1...\nOrganization wants strongest authentication for remote access.",
                "question": "What provides the highest level of authentication security?",
                "options": ["A) Strong password", "B) Two-factor authentication", "C) Biometrics only", "D) Smart card and PIN"],
                "correct": "D",
                "explanation": "Smart card (something you have) + PIN (something you know) = strong 2FA."
            },
            {
                "scenario": "FINAL EXAM Q2...\nDatabase breached. Attacker accessed password hashes with salt.",
                "question": "What additional protection would have made cracking harder?",
                "options": ["A) Longer salt", "B) Key stretching", "C) Encryption", "D) Unique salt per user"],
                "correct": "B",
                "explanation": "Key stretching (PBKDF2, bcrypt, scrypt) makes hashing computationally expensive. Use both salt AND key stretching."
            },
            {
                "scenario": "FINAL EXAM Q3...\nNew IoT devices being deployed. Security concerns about vulnerabilities.",
                "question": "What should be done FIRST to secure IoT devices?",
                "options": ["A) Network segmentation", "B) Change default credentials", "C) Disable unnecessary services", "D) All of the above"],
                "correct": "D",
                "explanation": "IoT security requires: change defaults, disable unnecessary services, segment network, patch regularly."
            },
            {
                "scenario": "FINAL EXAM Q4...\nCompany expanding to new country. Different data protection laws.",
                "question": "What must be considered when storing EU citizen data?",
                "options": ["A) HIPAA", "B) GDPR", "C) SOX", "D) PCI DSS"],
                "correct": "B",
                "explanation": "GDPR governs EU citizen data regardless of where company is located."
            },
            {
                "scenario": "FINAL EXAM Q5...\nYou're ready. This is your last question before the real exam.",
                "question": "What's the most important thing to remember for Security+?",
                "options": ["A) Memorize every port number", "B) Understand concepts and scenarios", "C) Know every acronym", "D) Speed is everything"],
                "correct": "B",
                "explanation": "Security+ tests understanding, not memorization. Read scenarios carefully, eliminate wrong answers. You got this."
            }
        ]
    }
]

DB_NAME = "secureghost.db"
current_dir = "~"
PWD = "/home/operator"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    c.execute("DROP TABLE IF EXISTS progress")
    c.execute("DROP TABLE IF EXISTS answers")
    
    c.execute('''CREATE TABLE IF NOT EXISTS progress
                 (id INTEGER PRIMARY KEY,
                  highest_unlocked INTEGER,
                  completed_missions TEXT,
                  last_played TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS answers
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  mission_id INTEGER,
                  question_num INTEGER,
                  correct BOOLEAN,
                  timestamp TEXT)''')
    
    c.execute("INSERT INTO progress VALUES (1, 1, '[]', ?)", 
             (datetime.now().isoformat(),))
    
    conn.commit()
    conn.close()

def get_progress():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    row = c.execute("SELECT * FROM progress WHERE id = 1").fetchone()
    conn.close()
    
    return {
        "highest_unlocked": row[1],
        "completed_missions": json.loads(row[2]),
        "last_played": row[3]
    }

def save_progress(progress):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""UPDATE progress SET highest_unlocked = ?, completed_missions = ?, last_played = ? WHERE id = 1""",
              (progress["highest_unlocked"], json.dumps(progress["completed_missions"]),
               datetime.now().isoformat()))
    conn.commit()
    conn.close()

def save_answer(mission_id, question_num, correct):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO answers (mission_id, question_num, correct, timestamp) VALUES (?, ?, ?, ?)",
              (mission_id, question_num, correct, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_stats():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    total = c.execute("SELECT COUNT(*) FROM answers").fetchone()[0]
    correct = c.execute("SELECT COUNT(*) FROM answers WHERE correct = 1").fetchone()[0]
    
    conn.close()
    
    accuracy = (correct / total * 100) if total > 0 else 0
    return {
        "total_questions": total,
        "correct_answers": correct,
        "accuracy": accuracy
    }

def print_slow(text, delay=0.02):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def show_help():
    console.print("\nAvailable Commands:\n", style="bold cyan")
    console.print("  ls                    List available levels")
    console.print("  cd [level_name]       Enter a specific level")
    console.print("  cd ..                 Go back to main directory")
    console.print("  pwd                   Print working directory")
    console.print("  cat README.md         View game information")
    console.print("  cat STUDY_PLAN.md     View 30-day study plan")
    console.print("  stats                 View your statistics")
    console.print("  help                  Show this help message")
    console.print("  clear                 Clear the screen")
    console.print("  exit                  Exit SecureGhxst")
    console.print("\nTip: You must complete each level to unlock the next one!", style="dim")
    console.print()

def show_banner():
    console.clear()
    console.print("\n========================================", style="bold green")
    console.print("         SECURE GHXST", style="bold green")
    console.print("========================================\n", style="bold green")
    console.print("Terminal Infiltration: Security+ Hacking Simulator", style="bold yellow")
    console.print("Made by ghxstsh3ll\n", style="dim")
    console.print("Enjoying this tool? Support development with coffee!", style="bold cyan")
    console.print("CashApp: $Ghxstsh3ll (100% optional)\n", style="bold yellow")

def show_readme():
    console.print("\n" + "="*70, style="green")
    console.print("README.md", style="bold yellow")
    console.print("="*70 + "\n", style="green")
    console.print("WELCOME TO SECUREGHOST\n", style="bold cyan")
    console.print("Pass Security+ in 30 Days - Linux Terminal Edition\n")
    console.print("HOW TO PLAY:")
    console.print("1. Type 'ls' to list available levels")
    console.print("2. Type 'cd [level_name]' to enter a level")
    console.print("3. Answer all 5 questions correctly to unlock next level")
    console.print("4. If you get ANY question wrong, the level restarts")
    console.print("5. Complete all 30 levels to master Security+\n")
    console.print("COMMANDS:")
    console.print("Type 'help' to see all available commands\n")
    console.print("TIPS:")
    console.print("- Read explanations carefully after each question")
    console.print("- Use 'cat STUDY_PLAN.md' to see daily focus areas")
    console.print("- Type 'stats' to track your progress\n")
    console.print("Enjoying SecureGhxst? Buy me a coffee!", style="bold green")
    console.print("CashApp: $Ghxstsh3ll\n", style="yellow")
    console.print("="*70 + "\n", style="green")

def show_study_plan():
    console.print("\n" + "="*70, style="green")
    console.print("STUDY_PLAN.md", style="bold yellow")
    console.print("="*70 + "\n", style="green")
    console.print("30-DAY SECURITY+ STUDY PLAN\n", style="bold cyan")
    
    study_plan = {
        1: "Port numbers and network protocols",
        2: "Wireless security (WEP, WPA, WPA2, WPA3)",
        3: "Malware types and characteristics",
        4: "Social engineering attacks",
        5: "Cryptography basics",
        6: "PKI and certificates",
        7: "Authentication and access control",
        8: "Firewall types and configuration",
        9: "Network architecture and design",
        10: "Cloud computing models",
        11: "Virtualization security",
        12: "Mobile device management",
        13: "Secure coding practices",
        14: "Vulnerability scanning",
        15: "Mid-point review and assessment",
        16: "Penetration testing methodologies",
        17: "Incident response procedures",
        18: "Security policies and governance",
        19: "Risk management",
        20: "Business continuity and disaster recovery",
        21: "Digital forensics",
        22: "Security monitoring (SIEM, IDS/IPS)",
        23: "Physical security controls",
        24: "Application security (SDLC)",
        25: "Secure protocols",
        26: "Practice exam 1",
        27: "Practice exam 2",
        28: "Practice exam 3",
        29: "Final review session",
        30: "Final exam simulation"
    }
    
    for day, topic in study_plan.items():
        console.print(f"Level {day:02d}: {topic}")
    
    console.print("\n" + "="*70 + "\n", style="green")

def list_levels(progress):
    console.print("\nAvailable Levels:\n", style="bold cyan")
    
    for mission in MISSIONS:
        level_name = f"level_{mission['id']:02d}_{mission['title']}"
        
        if mission["id"] <= progress["highest_unlocked"]:
            if mission["id"] in progress["completed_missions"]:
                status = "COMPLETED"
                color = "dim green"
            else:
                status = "UNLOCKED"
                color = "bold green"
        else:
            status = "LOCKED"
            color = "dim"
        
        console.print(f"  [{status:10s}] {level_name}", style=color)
    
    console.print(f"\nProgress: {len(progress['completed_missions'])}/{len(MISSIONS)} levels completed", style="yellow")
    console.print()

def run_level(mission, progress):
    global current_dir, PWD
    
    console.clear()
    console.print(f"\nEntering {PWD}/level_{mission['id']:02d}_{mission['title']}", style="bold cyan")
    console.print("="*70, style="green")
    console.print(f"\nLEVEL {mission['id']}: {mission['title']}", style="bold yellow")
    console.print(f"Domain: {mission['domain']}", style="cyan")
    console.print("\nMission Brief:", style="bold")
    print_slow(mission['brief'], 0.01)
    console.print("\nStarting level... You must answer ALL 5 questions correctly.", style="yellow")
    console.print("One wrong answer and you start over!\n", style="bold red")
    time.sleep(1)
    
    correct_count = 0
    
    for i, question in enumerate(mission["questions"], 1):
        console.print(f"\nQuestion {i}/5", style="bold cyan")
        console.print("-"*70, style="green")
        print_slow(question["scenario"], 0.01)
        console.print(f"\n{question['question']}\n", style="bold yellow")
        
        for option in question["options"]:
            console.print(f"  {option}")
        
        answer = Prompt.ask("\nYour answer", choices=["A", "B", "C", "D", "a", "b", "c", "d"]).upper()
        
        correct = answer == question["correct"]
        save_answer(mission["id"], i, correct)
        
        if correct:
            console.print("\nCORRECT! Access granted.", style="bold green")
            correct_count += 1
        else:
            console.print(f"\nINCORRECT! The correct answer was {question['correct']}", style="bold red")
            console.print("\nMISSION FAILED. Restarting level...", style="bold red")
        
        console.print(f"\nExplanation:", style="bold cyan")
        console.print(question['explanation'], style="dim")
        
        if not correct:
            time.sleep(3)
            return run_level(mission, progress)
        
        time.sleep(1)
    
    console.print("\n" + "="*70, style="green")
    console.print("LEVEL COMPLETE!", style="bold green")
    console.print(f"Perfect score: 5/5 questions correct", style="bold yellow")
    
    if mission["id"] not in progress["completed_missions"]:
        progress["completed_missions"].append(mission["id"])
        if progress["highest_unlocked"] < mission["id"] + 1 and mission["id"] < len(MISSIONS):
            progress["highest_unlocked"] = mission["id"] + 1
        save_progress(progress)
        
        if mission["id"] < len(MISSIONS):
            console.print(f"\nLevel {mission['id'] + 1} UNLOCKED!", style="bold cyan")
    
    console.print("\nType 'cd ..' to return to main directory", style="dim")
    console.print()
    
    current_dir = f"level_{mission['id']:02d}"
    PWD = f"/home/operator/secureghost/{current_dir}"

def show_stats(progress):
    stats = get_stats()
    
    console.print("\n" + "="*70, style="green")
    console.print("OPERATOR STATISTICS", style="bold yellow")
    console.print("="*70 + "\n", style="green")
    
    table = Table(show_header=False, box=box.SIMPLE)
    table.add_column("Metric", style="cyan", width=30)
    table.add_column("Value", style="green", width=20)
    
    table.add_row("Levels Completed", f"{len(progress['completed_missions'])}/{len(MISSIONS)}")
    table.add_row("Levels Unlocked", f"{progress['highest_unlocked']}/{len(MISSIONS)}")
    table.add_row("Total Questions Answered", str(stats['total_questions']))
    table.add_row("Correct Answers", str(stats['correct_answers']))
    table.add_row("Overall Accuracy", f"{stats['accuracy']:.1f}%")
    
    progress_pct = (len(progress['completed_missions']) / len(MISSIONS)) * 100
    table.add_row("Campaign Progress", f"{progress_pct:.1f}%")
    
    console.print(table)
    console.print()
    
    if stats['accuracy'] >= 90:
        console.print("Exceptional performance! You're ready for the exam!", style="bold green")
    elif stats['accuracy'] >= 80:
        console.print("Excellent work! Keep it up!", style="bold green")
    elif stats['accuracy'] >= 70:
        console.print("Good progress. Review weak areas.", style="yellow")
    else:
        console.print("Additional training recommended.", style="red")
    
    console.print("\nSupport SecureGhxst: CashApp $Ghxstsh3ll\n", style="bold yellow")

def main():
    global current_dir, PWD
    
    init_db()
    progress = get_progress()
    
    show_banner()
    time.sleep(1)
    
    console.print("System initialized. Type 'help' for commands.\n", style="green")
    
    in_level = False
    current_level = None
    
    while True:
        try:
            if in_level:
                prompt_text = f"operator@secureghost:{PWD}$"
            else:
                prompt_text = "operator@secureghost:~/secureghost$"
            
            cmd = Prompt.ask(f"[bold green]{prompt_text}[/bold green]").strip()
            
            if not cmd:
                continue
            
            parts = cmd.split()
            command = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []
            
            if command == "help":
                show_help()
            
            elif command == "clear":
                console.clear()
                if not in_level:
                    show_banner()
            
            elif command == "ls":
                if in_level:
                    console.print("\nNo files in this directory", style="dim")
                    console.print("Complete the level to return\n")
                else:
                    list_levels(progress)
            
            elif command == "pwd":
                console.print(f"\n{PWD}\n")
            
            elif command == "cat":
                if not args:
                    console.print("\ncat: missing file operand", style="red")
                    console.print("Try 'cat README.md' or 'cat STUDY_PLAN.md'\n")
                elif args[0].lower() == "readme.md":
                    show_readme()
                elif args[0].lower() == "study_plan.md":
                    show_study_plan()
                else:
                    console.print(f"\ncat: {args[0]}: No such file or directory\n", style="red")
            
            elif command == "stats":
                show_stats(progress)
            
            elif command == "cd":
                if not args:
                    console.print("\ncd: missing operand\n", style="red")
                    continue
                
                target = args[0]
                
                if target == "..":
                    if in_level:
                        in_level = False
                        current_level = None
                        current_dir = "~"
                        PWD = "/home/operator"
                        console.print("\nReturned to main directory\n", style="yellow")
                    else:
                        console.print("\nAlready in main directory\n", style="dim")
                
                elif target.startswith("level_"):
                    if in_level:
                        console.print("\nAlready in a level. Type 'cd ..' to exit first\n", style="red")
                        continue
                    
                    try:
                        level_num = int(target.split('_')[1])
                        mission = next((m for m in MISSIONS if m["id"] == level_num), None)
                        
                        if not mission:
                            console.print(f"\ncd: {target}: No such directory\n", style="red")
                            continue
                        
                        if level_num > progress["highest_unlocked"]:
                            console.print(f"\nLevel {level_num} is LOCKED", style="red")
                            console.print(f"Complete level {progress['highest_unlocked']} first\n", style="yellow")
                            continue
                        
                        in_level = True
                        current_level = mission
                        run_level(mission, progress)
                    
                    except (ValueError, IndexError):
                        console.print(f"\ncd: {target}: No such directory\n", style="red")
                
                else:
                    console.print(f"\ncd: {target}: No such directory\n", style="red")
            
            elif command == "exit" or command == "quit":
                console.print("\nLogging out of secure terminal...", style="yellow")
                time.sleep(0.5)
                console.print("Good luck on your Security+ exam, Operator.\n", style="green")
                break
            
            else:
                console.print(f"\n{command}: command not found", style="red")
                console.print("Type 'help' for available commands\n", style="dim")
        
        except KeyboardInterrupt:
            console.print("\n\nUse 'exit' to quit\n", style="yellow")
            continue

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\nEmergency shutdown initiated", style="red")
        console.print("Progress saved. Stay safe, Operator.\n", style="yellow")
