"""Built-in demo findings covering five NIST 800-53 controls."""

DEMO_FINDINGS = [
    {
        "weakness_name": "Privileged Account Review Not Performed",
        "weakness_description": (
            "Quarterly reviews of privileged user accounts (admin, service accounts) "
            "have not been conducted for over 12 months. Multiple stale accounts "
            "belonging to separated employees retain elevated permissions, increasing "
            "the risk of unauthorized access to sensitive federal data."
        ),
        "security_control": "AC-2",
        "severity": "Critical",
        "source": "Audit",
        "detection_date": "2026-01-15",
        "scheduled_completion": "2026-04-30",
        "office_org": "Office of Information Technology",
        "point_of_contact": "Jane Smith, ISSO",
        "resources_required": "IAM team (40 hrs), ISSO review time (8 hrs)",
        "remediation_plan": (
            "1. Immediately disable accounts of separated employees. "
            "2. Implement quarterly automated account review workflow in IAM system. "
            "3. Document review process in SSP and train account managers."
        ),
        "milestones": [
            "2026-02-01: Disable all separated employee privileged accounts",
            "2026-03-01: Deploy automated quarterly review workflow",
            "2026-04-15: Complete first formal quarterly review cycle",
            "2026-04-30: Update SSP and close finding",
        ],
        "status": "In Progress",
        "comments": (
            "15 stale privileged accounts identified; 12 disabled as of 2026-02-10. "
            "Automated workflow procurement in progress."
        ),
    },
    {
        "weakness_name": "Anti-Malware Signatures Out of Date on 23% of Endpoints",
        "weakness_description": (
            "A vulnerability scan revealed that 47 of 204 Windows endpoints are running "
            "anti-malware definitions more than 30 days old. Outdated signatures leave "
            "systems exposed to known malware families including recent ransomware variants "
            "targeting federal agencies."
        ),
        "security_control": "SI-3",
        "severity": "High",
        "source": "Vulnerability Scan",
        "detection_date": "2026-02-03",
        "scheduled_completion": "2026-05-15",
        "office_org": "Cybersecurity Operations Center",
        "point_of_contact": "Marcus Johnson, SOC Lead",
        "resources_required": "SOC team (20 hrs), endpoint management tooling (no additional cost)",
        "remediation_plan": (
            "1. Force-push current signatures to all affected endpoints via SCCM. "
            "2. Investigate root cause of update failures (network policy, agent issues). "
            "3. Configure alerting for endpoints exceeding 7-day signature staleness threshold."
        ),
        "milestones": [
            "2026-02-15: Emergency push of current signatures to all 47 affected endpoints",
            "2026-03-15: Root cause analysis complete and documented",
            "2026-04-15: Alerting configured and tested for signature staleness",
            "2026-05-15: Verify 100% endpoint compliance and close finding",
        ],
        "status": "In Progress",
        "comments": (
            "38 of 47 endpoints remediated as of 2026-02-20. Remaining 9 endpoints "
            "offline; will be addressed upon return to network."
        ),
    },
    {
        "weakness_name": "Unapproved Software Installed on Production Servers",
        "weakness_description": (
            "Configuration compliance scans identified 11 unauthorized software packages "
            "installed on production application servers, including peer-to-peer tools and "
            "unlicensed remote desktop utilities. These violate the approved software baseline "
            "and the organization's Configuration Management Policy."
        ),
        "security_control": "CM-6",
        "severity": "Medium",
        "source": "Vulnerability Scan",
        "detection_date": "2026-01-28",
        "scheduled_completion": "2026-06-01",
        "office_org": "Systems Administration",
        "point_of_contact": "David Lee, Senior SysAdmin",
        "resources_required": "SysAdmin team (16 hrs), change management process time",
        "remediation_plan": (
            "1. Remove all unauthorized software from affected servers immediately. "
            "2. Enforce application whitelisting via Group Policy on all production servers. "
            "3. Update baseline configuration documentation and conduct training."
        ),
        "milestones": [
            "2026-02-15: Remove unauthorized software from all 11 production servers",
            "2026-03-30: Deploy and test application whitelisting via Group Policy",
            "2026-05-01: Update baseline documentation and retrain SysAdmin staff",
            "2026-06-01: Rescan to confirm remediation and close finding",
        ],
        "status": "Open",
        "comments": (
            "Change request CR-2026-0089 submitted for removal. "
            "Awaiting change advisory board approval scheduled for 2026-02-25."
        ),
    },
    {
        "weakness_name": "Password Complexity Policy Not Enforced for Service Accounts",
        "weakness_description": (
            "A penetration test revealed that 8 service accounts use passwords that do not "
            "meet NIST SP 800-63B requirements: passwords are fewer than 15 characters, "
            "lack complexity, and have never been rotated. One service account password "
            "was found in a publicly accessible code repository."
        ),
        "security_control": "IA-5",
        "severity": "Critical",
        "source": "Penetration Test",
        "detection_date": "2025-12-10",
        "scheduled_completion": "2026-03-31",
        "office_org": "Identity & Access Management",
        "point_of_contact": "Sarah Chen, IAM Manager",
        "resources_required": "IAM team (24 hrs), application team coordination (16 hrs)",
        "remediation_plan": (
            "1. Immediately rotate the compromised service account credential exposed in repository. "
            "2. Rotate all 8 non-compliant service account passwords to 20+ character random strings. "
            "3. Store all service account credentials in approved secrets management vault. "
            "4. Implement 90-day automated rotation policy for all service accounts."
        ),
        "milestones": [
            "2025-12-11: Rotate compromised credential and revoke old token from repository",
            "2026-01-15: Rotate all 8 non-compliant service account passwords",
            "2026-02-28: Onboard all service accounts to secrets management vault",
            "2026-03-31: Automated 90-day rotation policy deployed and verified",
        ],
        "status": "In Progress",
        "comments": (
            "Compromised credential rotated on 2025-12-11 within 24 hours of discovery. "
            "Repository secret scanning enabled. 5 of 8 accounts migrated to vault."
        ),
    },
    {
        "weakness_name": "Unencrypted Sensitive Data on Backup Storage Media",
        "weakness_description": (
            "An audit finding identified that backup tapes containing PII and CUI are stored "
            "in an offsite facility without encryption at rest. If tapes are lost or stolen, "
            "sensitive federal data would be exposed without any cryptographic protection, "
            "violating FIPS 140-2 requirements for data at rest."
        ),
        "security_control": "SC-28",
        "severity": "High",
        "source": "Audit",
        "detection_date": "2025-11-20",
        "scheduled_completion": "2026-07-31",
        "office_org": "Data Management & Privacy Office",
        "point_of_contact": "Robert Torres, Data Management Officer",
        "resources_required": (
            "Encryption software licensing ($15,000), storage team (80 hrs), "
            "vendor coordination (40 hrs)"
        ),
        "remediation_plan": (
            "1. Procure FIPS 140-2 validated encryption solution for backup media. "
            "2. Encrypt all existing backup tapes before next offsite transfer. "
            "3. Update backup procedures to enforce encryption for all future backups. "
            "4. Conduct training for storage and operations team."
        ),
        "milestones": [
            "2026-01-31: Complete procurement of FIPS 140-2 validated encryption solution",
            "2026-03-31: Encrypt all existing backup tapes in offsite facility",
            "2026-05-31: Update backup runbooks and enforce encryption in backup scripts",
            "2026-07-31: Training complete; audit evidence gathered; finding closed",
        ],
        "status": "Risk Accepted",
        "comments": (
            "Temporary risk acceptance granted through 2026-01-31 pending procurement. "
            "Physical security controls at offsite facility verified as compensating control. "
            "Encryption procurement approved by CISO on 2026-01-10."
        ),
    },
]
