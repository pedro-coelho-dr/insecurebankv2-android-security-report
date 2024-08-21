# InsecureBankv2 Pentest Report

**Table of Contents**
- [InsecureBankv2 Pentest Report](#insecurebankv2-pentest-report)
  - [1. Introduction](#1-introduction)
  - [2. Methodology](#2-methodology)
  - [3. Tools](#3-tools)
  - [4. Objective](#4-objective)
  - [5. Scope](#5-scope)
  - [6. Reconnaissance](#6-reconnaissance)
  - [7. Executive Summary](#7-executive-summary)
  - [8. Vulnerabilities](#8-vulnerabilities)
    - [8.1 Improper Credential Usage: Hardcoded Backdoor Account](#81-improper-credential-usage-hardcoded-backdoor-account)
    - [8.2 Debuggin Enabled](#82-debuggin-enabled)
    - [8.3 Allow Backup](#83-allow-backup)
    - [8.4 Insufficient Cryptography](#84-insufficient-cryptography)

## 1. Introduction

This report details the results of a penetration test conducted by **Pedro Coelho** on the **[InsecureBankV2](https://github.com/dineshshetty/Android-InsecureBankv2)** Android application from 15 August 2024 to {{END}}. The goal of this assessment was to uncover potential security vulnerabilities and evaluate the application’s overall security posture. Key areas of focus included static and dynamic analysis, network communications, and code vulnerabilities. Each finding is categorized and accompanied by mitigation recommendations to help improve the security of the application.

## 2. Methodology

**1. Preparation**  
The scope and objectives for the pentest were defined. Tools including MobSF, Jadx, ADB, and Genymotion were set up. The testing environment was configured with the necessary settings.

**2. Reconnaissance**  
Initial information gathering was conducted using MobSF for both static and dynamic analysis. Permissions, manifest configurations, and potential entry points were examined. VirusTotal was utilized to check file reputations.

**3. Exploitation**  
Vulnerability exploitation was performed using tools such as Burp Suite, ADB, and Frida. These tools were used to analyze network traffic, identify security misconfigurations, and attempt direct exploitation, including bypassing authentication mechanisms.

**4. Reporting**  
All identified vulnerabilities were documented with supporting evidence. Each vulnerability was linked to relevant OWASP Mobile Top 10 and CWE references, assessed for impact and severity, and assigned a CVSS score. Mitigation steps were provided to guide remediation.

The vulnerabilities are presented with the following structure: *Title, Description, Evidence, OWASP Mobile Top 10 Reference, CWE Reference, Impact, CVSS Score* and *Mitigation*.
   
## 3. Tools

- **[OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)**
- **[OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)**
- **[Common Weakness Enumeration (CWE)](https://cwe.mitre.org/)**
- **[Common Vulnerability Scoring System (CVSS) 4.0 Calculator](https://www.first.org/cvss/calculator/4.0)**
- **[Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF)**
- **[VirusTotal](https://www.virustotal.com/)**
- **[Genymotion Desktop](https://docs.genymotion.com/desktop/)**
- **[Jadx](https://github.com/skylot/jadx)**
- **[ADB (Android Debug Bridge)](https://developer.android.com/studio/command-line/adb)**
- **[CyberChef](https://gchq.github.io/CyberChef/)**
- **[Kali Linux](https://www.kali.org/)**
- **[Docker](https://www.docker.com/)**
- **[VSCode](https://code.visualstudio.com/)**


## 4. Objective

The objective of this penetration test was to identify security vulnerabilities within the InsecureBankV2 Android application. The focus was on assessing the app's security posture through static and dynamic analysis, network communications, and code vulnerabilities. The goal was to provide actionable insights and recommendations to improve the security of the application.

## 5. Scope

The scope of the pentest was limited to the InsecureBankV2 Android application and its associated network communications. Testing included static analysis of the app’s code and configurations, dynamic analysis of its runtime behavior, and network traffic analysis. The assessment excluded any external systems or third-party integrations outside of the application itself.

{{ ADD ENVIROMENT INFO HERE }}  
{{ refers to README.md }}

## 6. Reconnaissance

MobSF Analysis
![alt text](img/mobsf-overview.png)

VirusTotal Overview

[Reference Link](https://www.virustotal.com/gui/file/b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b91f902d194a4)

![alt text](img/virustotal-overview.png)

MobSF Analysis

- Applications Permissions: 
    ```
    android.permission.ACCESS_COARSE_LOCATION  
    android.permission.ACCESS_NETWORK_STATE  
    android.permission.GET_ACCOUNTS  
    android.permission.INTERNET  
    android.permission.READ_CONTACTS  
    android.permission.READ_PROFILE  
    android.permission.SEND_SMS  
    android.permission.USE_CREDENTIALS  
    android.permission.WRITE_EXTERNAL_STORAGE	  
    ```    
- Manifest Analysis:  

  - **Debugging Enabled**:  `android:allowBackup=true` The app's debug mode is enabled, which makes it more susceptible to reverse engineering and exploitation by attackers.
  - **Allow Backup**: `android:debuggable=true` Allowing the app's data to be backed up via adb presents a significant data leakage risk, especially in environments where USB debugging is enabled.
  - **Exported Components**: `PostLogin, DoTransfer, ViewStatement, TrackUserContentProvider` Several critical components are exported, making them accessible to other apps on the device, potentially exposing the app to unauthorized access and security risks.
  - **StrandHogg 2.0 Vulnerability**: `PostLogin, DoTransfer, ViewStatement, ChangePassword` Multiple activities  are vulnerable to task hijacking attacks.
  
Jadx Analysis

![alt text](img/jadx-sourcecode-treelist.png)


## 7. Executive Summary


## 8. Vulnerabilities
- Debbugin Enabled
- Allow Backup




### 8.1 Improper Credential Usage: Hardcoded Backdoor Account

**Description**  
The app contains a hardcoded backdoor account using the username `devamin`, which allows login without a password. This vulnerability arises from the application’s improper credential management, where a specific condition in the code bypasses normal authentication.

**Evidence**  
During static analysis using Jadx, the following code snippet was identified:
![alt text](img/jadx-sourcecode-devadmin.png)

**OWASP Mobile Top 10 Reference**  
[M1: Improper Credential Usage](https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage.html)

**CWE Reference**  
[CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

**Impact**  
Unauthorized access to the application is possible without authentication, allowing complete control over user data and app functionality. This flaw severely compromises the security of the system.

**CVSS v4.0 Score**  
9.3 / Critical  
```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

**Mitigation**  
Remove the hardcoded credentials and replace them with secure storage mechanisms, such as environment variables or encrypted storage. Ensure proper authentication processes are enforced for all users.

### 8.2 Debuggin Enabled


**Description**  


**Evidence**  


**OWASP Mobile Top 10 Reference**  
[]()

**CWE Reference**  
[]()

**Impact**  

**CVSS v4.0 Score**  
 
```
```

**Mitigation**  





### 8.3 Allow Backup

**Description**  


**Evidence**  


**OWASP Mobile Top 10 Reference**  
[]()

**CWE Reference**  
[]()

**Impact**  

**CVSS v4.0 Score**  
 
```
```

**Mitigation**  




### 8.4 Insufficient Cryptography


**Description**  


**Evidence**  


**OWASP Mobile Top 10 Reference**  
[]()

**CWE Reference**  
[]()

**Impact**  

**CVSS v4.0 Score**  
 
```
```

**Mitigation**  





![alt text](img/adb-sharedpref-crypto.png)
![alt text](img/jadx-cryptoclass.png)
USER  
![alt text](img/cybefchef-user.png)
PASSWORD    
![alt text](img/cyberchef-pass.png)


---
**Author: Pedro Coelho** 

CESAR School  
Specialization in Cybersecurity  
Mobile Application Security Course  
Instructor: Erick Nascimento  

Recife, 2024