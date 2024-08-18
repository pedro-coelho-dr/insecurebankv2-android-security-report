# InsecureBankv2 Pentest Report


## Table of Contents
- [InsecureBankv2 Pentest Report](#insecurebankv2-pentest-report)
  - [Table of Contents](#table-of-contents)
  - [1. Objective](#1-objective)
  - [2. Scope](#2-scope)
  - [3. Methodology](#3-methodology)
    - [3.1 Reconnaissance](#31-reconnaissance)
      - [MobSF Overview](#mobsf-overview)
      - [VirusTotal Overview](#virustotal-overview)
    - [3.2 Static Analysis](#32-static-analysis)
      - [MobSF Static Analysis](#mobsf-static-analysis)
      - [Jadx Static Analysis](#jadx-static-analysis)
    - [3.3 Dynamic Analysis](#33-dynamic-analysis)
      - [Burp Suite](#burp-suite)
      - [Android Debug Bridge (ADB)](#android-debug-bridge-adb)
    - [3.4 Exploitation](#34-exploitation)
    - [3.5 Reporting](#35-reporting)
    - [3.6 Tools](#36-tools)
  - [4. Executive Summary](#4-executive-summary)
  - [5. Vulnerabilities](#5-vulnerabilities)
  - [Author](#author)

## 1. Objective
https://github.com/dineshshetty/Android-InsecureBankv2

## 2. Scope

## 3. Methodology

### 3.1 Reconnaissance

#### MobSF Overview
![alt text](img/mobsf-overview.png)

#### VirusTotal Overview

[Reference Link](https://www.virustotal.com/gui/file/b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b91f902d194a4)

![alt text](img/virustotal-overview.png)

### 3.2 Static Analysis

#### MobSF Static Analysis

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
  - **StrandHogg 2.0 Vulnerability**: `PostLogin, DoTransfer, ViewStatement, ChangePassword` Multiple activities  are vulnerable to task hijacking attacks.
  - **Debugging Enabled**:  `android:allowBackup=true` The app's debug mode is enabled, which makes it more susceptible to reverse engineering and exploitation by attackers.
  - **Allow Backup**: `android:debuggable=true` Allowing the app's data to be backed up via adb presents a significant data leakage risk, especially in environments where USB debugging is enabled.
  - **Exported Components**: `PostLogin, DoTransfer, ViewStatement, TrackUserContentProvider` Several critical components are exported, making them accessible to other apps on the device, potentially exposing the app to unauthorized access and security risks.
  
- APKiD Analysis
  - The application employs anti-VM techniques `Build.MODEL check, Build.MANUFACTURER check, Build.PRODUCT check` to detect if it is running in a virtualized environment, potentially complicating analysis by automated tools or in an emulated environment. Additionally, the `dexmerge` manipulations indicate that the DEX files have likely undergone some form of compilation or merging process, which could obfuscate the app's behavior and make reverse engineering more challenging.



#### Jadx Static Analysis

### 3.3 Dynamic Analysis

#### Burp Suite

#### Android Debug Bridge (ADB)

### 3.4 Exploitation

### 3.5 Reporting

### 3.6 Tools
- **[Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF)**
- **[VirusTotal](https://www.virustotal.com/)**
- **[Docker](https://www.docker.com/)**
- **[VSCode](https://code.visualstudio.com/)**

## 4. Executive Summary

## 5. Vulnerabilities

### 5.1 




## Author
Pedro Coelho  
CESAR School  
Specialization in Cybersecurity  
Mobile Application Security Course  
Instructor: Erick Nascimento