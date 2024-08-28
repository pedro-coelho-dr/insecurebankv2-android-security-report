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
    - [8.1 Hardcoded Backdoor Account](#81-hardcoded-backdoor-account)
    - [8.2 Debugging Enabled](#82-debugging-enabled)
    - [8.3 Allow Backup Enabled](#83-allow-backup-enabled)
    - [8.4 Weak Cryptography in User Data Storage](#84-weak-cryptography-in-user-data-storage)
    - [8.5 Bypass of Root Detection](#85-bypass-of-root-detection)
    - [8.6  Insecure HTTP Connections](#86--insecure-http-connections)
    - [8.7  Plaintext Transmission of Sensitive Information](#87--plaintext-transmission-of-sensitive-information)
    - [8.8 Improper Access Control on Password Change](#88-improper-access-control-on-password-change)
    - [8.9 Enumeration of Usernames via Endpoints](#89-enumeration-of-usernames-via-endpoints)
    - [8.10 Bypassing Login to Access PostLogin Activity Directly](#810-bypassing-login-to-access-postlogin-activity-directly)
    - [8.11 Binary Patching](#811-binary-patching)
    - [8.12 Create User Button Activation through Hidden Value Manipulation](#812-create-user-button-activation-through-hidden-value-manipulation)
    - [CERTIFICATE PINNING](#certificate-pinning)
    - [EMULATOR DETECTION](#emulator-detection)
    - [JAVASCRIPT CODE IN external storage for VIEW STATEMENT](#javascript-code-in-external-storage-for-view-statement)

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
- **[Frida](https://frida.re/)**
- **[Objection](https://github.com/sensepost/objection)**
- [Apktool]
- [keytool]
- [apksigner]
- **[CyberChef](https://gchq.github.io/CyberChef/)**
- **[Burp Suite](https://portswigger.net/burp)**
- **[Kali Linux](https://www.kali.org/)**
- **[Docker](https://www.docker.com/)**
- **[VSCode](https://code.visualstudio.com/)**


## 4. Objective

The objective of this penetration test was to identify security vulnerabilities within the InsecureBankV2 Android application. The focus was on assessing the app's security posture through static and dynamic analysis, network communications, and code vulnerabilities. The goal was to provide actionable insights and recommendations to improve the security of the application.

## 5. Scope

The scope of the pentest was limited to the InsecureBankV2 Android application and its associated network communications. Testing included static analysis of the app’s code and configurations, dynamic analysis of its runtime behavior, and network traffic analysis. The assessment excluded any external systems or third-party integrations outside of the application itself.

**Environment**  
- Host Machine: *Windows 11, Intel i7, 32GB RAM.*  
- Emulator: *Genymotion Desktop Version 3.7.1*, configured to emulate a *Samsung Galaxy S8* with *Android 10.0.*  
- Network Environment: The Genymotion emulator connects to the internet via the host machine. The InsecureBankV2 app is configured to communicate with an external server using IP and port provided by the instructor. 

For setup details, refer to [readme](./readme.md).

## 6. Reconnaissance

**VirusTotal Overview**   

![alt text](img/virustotal-overview.png)  

The APK file was analyzed on VirusTotal, where 12 out of 68 security vendors flagged it as malicious. Common labels included Trojan and Potentially Unwanted Program (PUP). The APK was last analyzed on August 3, 2024, with popular detections from vendors like Google, Sophos, and McAfee flagging potential spyware behavior. Additionally, the APK exhibited behaviors such as sending SMS, using obfuscation techniques, and checking for GPS and telephony data, which are often associated with malware or suspicious applications.

VirusTotal also provided a comprehensive view of the APK's reputation, certificate attributes, and contacted domains/IPs, which contributed to assessing the app's overall risk.


[Reference Link](https://www.virustotal.com/gui/file/b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b91f902d194a4)




**MobSF Analysis**

![alt text](img/mobsf-overview.png)  

The MobSF static analysis identified critical security risks within the InsecureBankV2 Android application, such as the use of weak cryptography, exposed activities vulnerable to task hijacking, and the presence of debugging and backup functionalities that leave the app open to reverse engineering and data leakage. The analysis also revealed improper use of permissions, insecure components, and potential vulnerabilities like the Janus signature vulnerability.


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

[Full Report](pdf/insecurebankv2.pdf)
  
**Jadx Analysis**

Jadx was used to decompile the APK, revealing hardcoded credentials, encryption implementations, authentication logic, app flow,  permissions and manifest configurations, providing insights into possible vulnerabilities in the app's code.  

![alt text](img/jadx-sourcecode-treelist.png)

**Burp Suite Analysis**  
Burp Suite was employed to intercept network traffic and analyze HTTP requests made by the app. This provided insight into the app's communication patterns and any potential security weaknesses in the data being transmitted.  

![alt text](img/burp-sitemap.png)


## 7. Executive Summary


## 8. Vulnerabilities

### 8.1 Hardcoded Backdoor Account

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

### 8.2 Debugging Enabled

**Description**  
The `android:debuggable` flag is set to `true` in the `AndroidManifest.xml` file, indicating that the app is compiled in debug mode. This leaves the app vulnerable to reverse engineering and unauthorized access using tools such as Android Debug Bridge (ADB). In production environments, leaving this flag enabled increases the risk of attacks, allowing attackers to intercept and manipulate app data and behavior.

**Evidence**  
During static analysis using Jadx, the following code snippet was found in the `AndroidManifest.xml` file:
![alt text](/img/jadx-debuggable.png)

**OWASP Mobile Top 10 Reference**  
[M8: Security Misconfiguration](https://owasp.org/www-project-mobile-top-10/2023-risks/m8-security-misconfiguration.html)

**CWE Reference**  
[CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)

**Impact**  
An attacker can attach a debugger to the app, inspect and modify its runtime behavior, access sensitive data, and bypass security controls, putting the app and user data at significant risk.kal

**CVSS v4.0 Score**  
5.1 / Medium
```
CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N
```
**Mitigation**  
 Ensure that the `android:debuggable` flag is set to `false` for production releases. The following line should be added or modified in the `AndroidManifest.xml`:

```
<application
    android:debuggable="false">
</application>
```
This will prevent attackers from attaching a debugger to the application in production environments.

### 8.3 Allow Backup Enabled

**Description**  
The `android:allowBackup` flag is set to `true` in the `AndroidManifest.xml` file. This setting allows the app's data to be backed up via ADB without requiring the user's consent. If an attacker gains access to the device, they can extract the app's private data by using ADB backup functionality, which could result in data leakage or exposure of sensitive information.

**Evidence**  
During static analysis using Jadx, the following code snippet was found in the `AndroidManifest.xml` file:  
![alt text](img/jadx-allowbackup.png)  
You can further verify this by running the following ADB command:  
![alt text](img/adb-backup1.png)
![alt text](img/adb-backup2.png)

**OWASP Mobile Top 10 Reference**  
[M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage.html)

**CWE Reference**  
[CWE-530: Exposure of Backup File to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/530.html)S

**Impact**  
An attacker who gains access to the device or ADB can extract and analyze the backup of the app, leading to the exposure of sensitive user information, including login credentials, private files, and cached data.

**CVSS v4.0 Score**  
 7.0 / High
```
CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N
```

**Mitigation**  
To mitigate this risk, set `android:allowBackup="false"` in the `AndroidManifest.xml` file:

```
<application
    android:allowBackup="false">
</application>
```
This will prevent the app's data from being backed up by ADB, thereby protecting the app’s sensitive data from unauthorized extraction.



### 8.4 Weak Cryptography in User Data Storage


**Description**  
The app stores sensitive information such as usernames and passwords in the `mySharedPreferences.xml` using weak encryption. While the data appears encrypted at first glance, further inspection reveals a hardcoded cryptographic key and an insecure implementation of AES (Advanced Encryption Standard) in Cipher Block Chaining (CBC) mode. An attacker with access to the device can easily retrieve and decrypt this data, leading to the exposure of sensitive user information.

**Evidence**  

- Access to Encrypted Data via ADB  
Using ADB, the app's shared preferences file `mySharedPreferences.xml` was accessed, which stores encrypted usernames and passwords.  
![alt text](img/adb-sharedpref-crypto.png)
- Decryption Process  
Upon inspecting the app's source code using Jadx, the CryptoClass.java file was identified, revealing the hardcoded cryptographic key used for encryption:  
![alt text](img/jadx-cryptoclass.png)

This key, along with a static Initialization Vector (IV), was used in AES/CBC mode to encrypt the stored data. Using these values, the data was easily decrypted using CyberChef.   
 
![alt text](img/cybefchef-user.png)  
   
![alt text](img/cyberchef-pass.png)  


**OWASP Mobile Top 10 Reference**  
[M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage.html)

**CWE Reference**  
[CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
[CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)  

**Impact**  
An attacker with access to the device can decrypt sensitive user information stored in the app's SharedPreferences. This vulnerability compromises the confidentiality of usernames, passwords, and other private information, potentially leading to account takeover or other security breaches.

**CVSS v4.0 Score**  
6.9 / Medium
```
CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N
```

**Mitigation**  

- Use Strong Cryptography  
Replace the hardcoded cryptographic key with dynamically generated keys stored securely using the Android Keystore system.  

- Secure Initialization Vectors (IV)  
Generate a random IV for each encryption operation instead of using a static IV to ensure the ciphertext is unique for each encrypted data item.  

- Use EncryptedSharedPreferences  
Utilize Android's EncryptedSharedPreferences for securely storing sensitive information like usernames and passwords, which handles encryption properly and securely.   

- Remove Hardcoded Credentials:  
Eliminate hardcoded keys from the codebase to prevent easy decryption and exposure of sensitive data by attackers.


### 8.5 Bypass of Root Detection

**Description** 

The InsecureBankV2 application implements a basic root detection mechanism in the `PostLogin` activity by checking the existence of the su binary and the Superuser.apk file. This detection can be easily bypassed using tools such as Frida and Objection. By dynamically hooking and modifying the return values of the `doesSUexist()` and `doesSuperuserApkExist()` methods, the app can be tricked into believing that the device is not rooted.


**Evidence**  

- Application Displays Rooted Status  
Before the bypass, the application detects that the device is rooted and displays the message `Rooted Device!!`.  

  ![alt text](img/app-rooted.png)
- Root Detection Code in Jadx  
The root detection logic is implemented in the PostLogin activity and is based on checking the existence of the su binary and Superuser.apk file.  
  ![alt text](img/jadx-postlogin-root.png)  

- Frida Server Running  
The Frida server is successfully running on the device, allowing runtime hooking of methods for bypassing the root detection.    
  ![alt text](img/frida-server-running.png)

- Objection Command for Root Detection Bypass  
Using Objection, the root detection checks were bypassed by setting the return values of the doesSUexist() and doesSuperuserApkExist() methods to false.

  ```bash
  objection -g com.android.insecurebankv2 explore
  ```  

  `android hooking set return_value <class.method> <value>`
  ```bash
  android hooking set return_value com.android.insecurebankv2.PostLogin.doesSUexist false
  android hooking set return_value com.android.insecurebankv2.PostLogin.doesSuperuserApkExist false
  ```  
  ![alt text](img/objection-unroot.png)
S
- Application Displays Not Rooted Status
After bypassing the root detection, the application now displays the message `Device not Rooted!!`, indicating that the root detection has been successfully disabled.  

  ![alt text](img/app-not-rooted.png)

**OWASP Mobile Top 10 Reference**  
[M7: Insufficient Binary Protection](https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protection.html)

**CWE Reference**  
[CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)  
[CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)


**Impact**  
By bypassing root detection, attackers gain full access to the application’s features on a rooted device, leading to increased risks of data exposure, tampering, and reverse engineering. Rooted devices provide deep access to the system and app data, which would normally be protected. When root detection is bypassed, attackers can:

- Extract sensitive data
- Modify the app or alter its behavior
- Circumvent security measures that protect the app in non-rooted environments
- Exploit other vulnerabilities more easily due to elevated privileges
  
The primary concern is that bypassing root detection allows attackers to operate with the privileges of a rooted device, while the application remains unaware and continues to function as though it were in a secure, non-rooted environment.

**CVSS v4.0 Score**  
8.4 / High
```
CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

**Mitigation**  
- Stronger Root Detection: Use advanced root detection techniques like or approaches that check system integrity, detect root management tools, and look for tampering with system files.
- Server-Side Enforcement: Implement server-side validation to enforce security measures and monitor for tampering or bypass attempts, ensuring security remains intact even if client-side detection is bypassed.
- Tamper Detection: Add tamper-detection mechanisms to detect runtime manipulation or debugging, preventing tools from altering app behavior.
- Monitor and Respond: Monitor app behavior for anomalies. Upon detecting tampering, trigger a response like logging the user out or disabling functionality.

### 8.6  Insecure HTTP Connections

**Description**  
The application communicates with the server using the insecure HTTP protocol instead of HTTPS. This lack of encryption leaves all data transmitted between the client and the server vulnerable to interception by attackers via man-in-the-middle (MITM) attacks. Using HTTP without encryption compromises the confidentiality and integrity of the data, including non-sensitive information, increasing the overall security risk of the application.


**Evidence**  
Using Burp Suite, the HTTP traffic between the application and the server was intercepted. The traffic was transmitted without any encryption, allowing it to be easily captured and analyzed.

- Setup: A manual proxy was configured in the emulator’s WiFi settings, directing traffic through Burp Suite. The Burp Suite CA certificate was installed on the device to allow interception of HTTPS traffic. HTTP traffic was intercepted and analyzed, revealing the unencrypted transmission of sensitive data.

  ![alt text](img/burp-setup-proxy.png)

  ![alt text](img/app-setup-proxy.png)  

- Captured HTTP Traffic: The traffic intercepted was entirely unencrypted, exposing all transmitted data.

  ![alt text](img/burp-request-response.png)  


**OWASP Mobile Top 10 Reference**  
[M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication.html)

**CWE Reference**  
[CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)


**Impact**  
An attacker intercepting this traffic can gain access to users' credentials, leading to potential account compromises, identity theft, and unauthorized access to sensitive user data.

**CVSS v4.0 Score**  
9.3 / Critical

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

**Mitigation**  
- Switch to HTTPS: Ensure all communications between the app and the server are encrypted using the HTTPS protocol.  
- Regularly Monitor and Enforce Security Standards: Continuously monitor network communications for compliance with security protocols.


### 8.7  Plaintext Transmission of Sensitive Information

**Description**  
The application transmits sensitive information, such as usernames and passwords, over the network in plaintext. This vulnerability allows attackers to intercept these credentials easily if they gain access to the network, especially in scenarios where the network is unsecured, such as public Wi-Fi. Even if HTTPS is not implemented, the transmission of sensitive information in plaintext exacerbates the risk.


**Evidence**  
During network traffic analysis with Burp Suite, the login credentials were intercepted and found to be transmitted in plaintext over the HTTP protocol.

- Captured Login Request: The intercepted request clearly shows the username and password being transmitted without any encryption.

  ![alt text](img/burp-request-response.png)  


**OWASP Mobile Top 10 Reference**  
[M5: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication.html)

**CWE Reference**  
[CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)


**Impact**  
An attacker intercepting this traffic can gain access to users' credentials, leading to potential account compromises, identity theft, and unauthorized access to sensitive user data.

**CVSS v4.0 Score**  
9.3 / Critical

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

**Mitigation**  
- Encrypt Sensitive Data: Always encrypt sensitive information before transmission, ideally by using HTTPS.  

- Implement Secure Communication Practices: Enforce secure coding practices that prevent sensitive information from being sent in plaintext.

### 8.8 Improper Access Control on Password Change

**Description**  
The application allows users to change another user's password by simply knowing their username. This vulnerability arises due to the lack of proper access control in the `/changepassword` endpoint. The application does not verify the identity of the user initiating the password change request, allowing any authenticated user to change the password of another user by sending a specially crafted request with the target's username.

**Evidence**  
By using Burp Suite, the password change request was intercepted and modified. The username of another user (jack) was entered along with a new password (senha). The application accepted the request and changed the password of jack without any further validation. The request and response are shown below:

- Password Change Request/Response  

![alt text](img/burp-changepassword.png)

- Login with New Password  
After changing the password, an attempt was made to log in as `jack` with the new password (`senha`). The login was successful, confirming that the password change was executed.  

![alt text](img/burp-login-test.png)

**OWASP Mobile Top 10 Reference**  
[M3: Insecure Authentication/Authorization](https://owasp.org/www-project-mobile-top-10/2023-risks/m3-insecure-authentication-authorization.html)

**CWE Reference**  
[CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

**Impact**  
This vulnerability allows an attacker to compromise the account of any user simply by knowing their username. The attacker can reset the user's password and gain full access to their account, leading to potential data theft, unauthorized transactions, or further attacks within the application. This poses a critical risk to the application's security and user privacy.


**CVSS v4.0 Score**   
8.6 / High  
 
```
CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

**Mitigation**  
- Implement Proper Access Control: Ensure that the user initiating the password change request is the same user whose password is being changed. This can be done by requiring authentication and verifying session tokens or using OAuth 2.0 mechanisms.  
  
- Use Multi-factor Authentication (MFA): Implement MFA for sensitive operations like password changes to ensure additional layers of security.  
  
- Require Current Password: Enforce a policy where users must provide their current password to change their password, reducing the risk of unauthorized changes.  
  

### 8.9 Enumeration of Usernames via Endpoints

**Description**  
The application is vulnerable to username enumeration through `/login` and other endpoints. An attacker can determine whether a username is valid by observing the server's responses to login attempts and password change requests. This issue becomes critical when combined with the password change vulnerability, allowing an attacker to identify valid usernames and then reset their passwords without the need for further credentials.

**Evidence**  
- Using Burp Suite’s Intruder tool, different usernames were tested against the `/login` endpoint. The application returned distinct responses for valid and invalid usernames:

  ![alt text](img/burp-intruder-enumeration.png)  

- Invalid Username: The server responds with an error indicating the user does not exist.  
  
  ![alt text](img/burp-response-user-does-not-exist.png)  
- Valid Username: The server either proceeds with the login process, confirming the username’s existence.
  
  ![alt text](img/burp-response-user-exists.png)  

  ![alt text](img/burp-response-correct-cred.png)  

**OWASP Mobile Top 10 Reference**   
[M3: Insecure Authentication/Authorization](https://owasp.org/www-project-mobile-top-10/2023-risks/m3-insecure-authentication-authorization.html)

**CWE Reference**  
[CWE-203: Observable Discrepancy](https://cwe.mitre.org/data/definitions/203.html)

**Impact**  
This vulnerability allows attackers to identify valid usernames and, in combination with the password change flaw, reset passwords and gain unauthorized access to user accounts. This significantly increases the risk of account takeovers, data breaches, and unauthorized transactions.

**CVSS v4.0 Score**  
9.3 / Critical
```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N
```

**Mitigation**  

- Standardize Error Messages: Ensure that the server returns the same error message for both valid and invalid usernames.  
- Rate Limiting: Implement rate limiting on endpoints to slow down automated attacks.  
- Account Lockout: Introduce account lockout mechanisms after multiple failed attempts.  
- Multi-Factor Authentication: Implement MFA to protect accounts even if a username is compromised.  

### 8.10 Bypassing Login to Access PostLogin Activity Directly

**Description**  
The application allows an attacker to bypass authentication and directly access sensitive activities, such as `PostLogin`, by using simple ADB commands. This vulnerability arises because the app does not enforce proper access control on activities, leaving them accessible even without proper authentication. Using static analysis with Jadx, it was observed that other activities, such as `LoginActivity` `DoTransfer`, `ViewStatement`, and `ChangePassword`, also lack proper access restrictions.

An attacker can exploit this issue by launching these activities directly, bypassing the login mechanism and accessing sensitive functionalities.


**Evidence**  
The following ADB command was executed to directly launch the PostLogin activity without authentication:  

```bash
adb shell am start -n com.android.insecurebankv2/com.android.insecurebankv2.PostLogin
```

- Command Execution:  
  
  ![alt text](/img/adb-postlogin.png)  

- Resulting Screen (PostLogin Activity):  
  
  ![alt text](/img/app-postlogin.png)

**OWASP Mobile Top 10 Reference**  
[M3: Insecure Authentication/Authorization](https://owasp.org/www-project-mobile-top-10/2023-risks/m3-insecure-authentication-authorization.html)

**CWE Reference**  
[CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

**Impact**  
An attacker can bypass authentication and directly access critical functionalities, such as transferring funds, without needing to log in. This compromises the confidentiality and integrity of the application, allowing unauthorized users to manipulate sensitive features.

**CVSS v4.0 Score**  
8.4 / High
```
CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

**Mitigation**  
- Enforce Access Control: Ensure that all sensitive activities are accessible only after proper user authentication.

- Activity Lifecycle Validation: Implement checks within the lifecycle methods of all sensitive activities to verify the user's authentication status and redirect unauthenticated users to the login screen.

- Prevent External Access: Secure all activities by preventing them from being launched externally through ADB or other methods unless proper permissions are verified.


### 8.11 Binary Patching

**Description**  

The application was modified through binary patching, where the APK was decompiled, specific code sections were altered, and then recompiled. This allowed for the reinstallation of the modified APK on the Android device, bypassing any integrity checks or security mechanisms. Such modifications can be used to introduce malicious functionality, enable hidden features, or remove security controls.

**Evidence**  

- The APK was decompiled using Apktool:

  ```bash
  apktool d -r InsecureBankv2.apk
  ```
- Specific code was modified to alter the application's behavior, as shown in the decompiled code snippet:
  
  ![alt text](img/jadx-hiddenbutton.png)

- The value on the LoginActivity.smali, setVisibility was set to 0x0, making the "Create User" button visible in the application, refer to [8.12 Create User Button Activation through Hidden Value Manipulation](#812-create-user-button-activation-through-hidden-value-manipulation):

  ![alt text](img/apktool-code.png)

- The modified APK was recompiled and signed with a new key:

  ```bash
  pktool InsecureBankv2 -o IB-2.apk

  keytool -genkey -v -keystore android.keystore -alias keydroid -keyalg RSA -keysize 2048 -validity 10000

  apksigner sign --ks-key-alias keydroid --ks android.keystore ib3.apk
  ```

- The APK was successfully reinstalled on the emulator, demonstrating the feasibility of this attack.

**OWASP Mobile Top 10 Reference**  
[M7: Insufficient Binary Protection]()

**CWE Reference**  
[CWE-494: Download of Code Without Integrity Check]()

**Impact**  
An attacker with access to the APK file can modify its functionality and repackage it, potentially introducing malicious code or enabling hidden features. This compromises the integrity of the application and poses significant security risks, including data theft, unauthorized access, or the propagation of malware.

**CVSS v4.0 Score**  
8.6 / High
```
CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

**Mitigation**  
- Implement strong integrity checks, such as using a combination of hash validation and certificate pinning, to prevent the installation of modified APKs.
- Employ obfuscation and anti-tampering techniques to make binary patching more difficult.
- Monitor for unusual application behavior that may indicate tampering.


### 8.12 Create User Button Activation through Hidden Value Manipulation

**Description**  

The application contains a hidden "Create User" feature that is not intended to be accessible by users. However, through manipulation of a hidden value in the APK code, this feature can be activated. Although the feature does not successfully allow the creation of a new user, its presence and potential activation illustrate a significant security vulnerability that could lead to unintended access to application features or expose sensitive operations.

**Evidence**  

- The hidden value controlling the visibility of the "Create User" button was identified and altered in the decompiled APK code, refer to [8.11 Binary Patching](#811-binary-patching), after recompiling and reinstalling the APK, the "Create User" button was made visible in the application:  

  ![alt text](img/app-create-user.png)  

  ![alt text](img/app-createusermsg.png)

- Attempting to create a user resulted in an error, as the feature is not fully functional, but the presence of the button illustrates the potential for feature exposure.

  ![alt text](img/jadx-createusermsg.png)

**OWASP Mobile Top 10 Reference**  
[M1: Improper Platform Usage]()

**CWE Reference**  
[CWE-285: Improper Authorization]()

**Impact**  
The ability to activate hidden features through code manipulation poses a security risk by exposing parts of the application that were not intended for user interaction. This can lead to unintended access to sensitive functions, compromising the security of the application and potentially enabling further exploitation.

**CVSS v4.0 Score**  
6.5 / Medium
```
CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:R/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N
```

**Mitigation**  
- Remove or securely disable any code related to hidden or debug features before deploying the application.
- Ensure that feature toggles are properly secured and inaccessible through simple code modification or reverse engineering.
- Regularly audit the application for the presence of unintended features or code paths that should not be accessible in production environments.




### CERTIFICATE PINNING

### EMULATOR DETECTION

### JAVASCRIPT CODE IN external storage for VIEW STATEMENT

https://github.com/micro-joan/BlackStone


---
**Author: Pedro Coelho** 

CESAR School  
Specialization in Cybersecurity  
Mobile Application Security Course  
Instructor: Erick Nascimento  

Recife, 2024