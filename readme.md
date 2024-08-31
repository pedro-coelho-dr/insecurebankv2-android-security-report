# Mobile Application Security Report: InsecureBankv2

This project is a part of the `Mobile Application Security Course` for the `Specialization in Cybersecurity` at `CESAR School`. It involves a security assessment of the InsecureBankV2 Android application, a purposely vulnerable app designed for testing. The report provides insights into identified vulnerabilities, along with recommendations for improving the app’s security.

### [Read the Full Report](report.md)

## Table of Contents
- [Mobile Application Security Report: InsecureBankv2](#mobile-application-security-report-insecurebankv2)
    - [Read the Full Report](#read-the-full-report)
  - [Table of Contents](#table-of-contents)
  - [Getting started](#getting-started)
    - [InsecureBankV2](#insecurebankv2)
    - [Genymotion](#genymotion)
    - [MobSF](#mobsf)
    - [Burp Suite](#burp-suite)
    - [ADB (Android Debug Bridge)](#adb-android-debug-bridge)
    - [Jadx](#jadx)
    - [Frida](#frida)
    - [Objection](#objection)
  - [Tools](#tools)
  - [Author](#author)


## Getting started

### InsecureBankV2

Download the Latest APK from the InsecureBankV2 repository:  

[InsecureBankV2](https://github.com/dineshshetty/Android-InsecureBankv2)

Transfer the APK to Genymotion by dragging and dropping the file into the emulator or using ADB:

```bash
adb install InsecureBankv2.apk
```

### Genymotion

Download and install [Genymotion Desktop](https://www.genymotion.com/)

Configure an Android device, this project uses the following environment:
 
**Environment**  
- Host Machine: *Windows 11, Intel i7, 32GB RAM, with the latest security updates applied.*  
- Emulator: *Genymotion Desktop Version 3.7.1*, configured to emulate a *Samsung Galaxy S8* with *Android 10.0.*  
- Network Environment: The Genymotion emulator is connected to the internet via the host machine. A manual proxy is configured to route traffic through security testing tools. The InsecureBankV2 app communicates with an external server using the IP and port provided by the instructor.


### MobSF

Run locally:
```bash
docker pull opensecurity/mobile-security-framework-mobsf:latest
```
```bash
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```
```bash
https://localhost:8000
```

Alternatively, run online:

[MobSF Online](https://mobsf.live/)


### Burp Suite

Download and Install [Burp Suite](https://portswigger.net/burp)

Install the [Burp Certificate](https://portswigger.net/burp/documentation/desktop/mobile/config-android-device) on the Android device. 

Set up the proxy in Burp Suite    

![alt text](/img/burp-setup-proxy.png)  

Configure WiFi settings on the Genymotion emulator to use the Burp proxy.  

![alt text](/img/app-setup-proxy.png)


### ADB (Android Debug Bridge)

Install ADB on your machine.

In Kali Linux, install ADB using the following command:

```bash
sudo apt install adb
```

For general instructions, refer to the [Android Developer Guide](https://developer.android.com/studio/command-line/adb).

Connect to your Genymotion emulator:
    
```bash
adb connect <emulator_ip>:<port>
```

Access the shell:
    
```bash
adb shell
```

### Jadx
Install Jadx on your machine.
For general instructions, refer to the [Jadx GitHub Repository](https://github.com/skylot/jadx)

On Kali Linux, run the following commands:
```bash
sudo apt install jadx
```
Open the GUI:
```bash	
jadx-gui
```


### Frida

Download the appropriate Frida-server binary for your emulator:  
[Frida Releases](https://github.com/frida/frida/releases)

This project used the following Frida-server binaries:
```bash
wget https://github.com/frida/frida/releases/download/16.4.8/frida-server-16.4.8-android-x86.xz
```
```bash
unxz frida-server-16.4.8-android-x86.xz
```
```bash
adb push frida-server-16.4.8-android-x86 /data/local/tmp/
```
Connect to the ADB shell, navigate to the directory, change permissions, and run the server:
```bash
cd /data/local/tmp/
```
```bash
adb shell chmod 777 frida-server-16.4.8-android-x86
```
```bash
./frida-server-16.4.8-android-x86
```

### Objection

Install Objection:

For further information, refer to the [Objection GitHub Repository](https://github.com/sensepost/objection)

```bash
pip3 install objection
```

To see the running processes on the device:

```bash
frida-ps -U
```

```bash
objection -g com.android.insecurebankv2 explore
```  


## Tools
- **[OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)**
- **[OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)**
- **[Common Weakness Enumeration (CWE)](https://cwe.mitre.org/)**
- **[Common Vulnerability Scoring System (CVSS) 4.0 Calculator](https://www.first.org/cvss/calculator/4.0)**
- **[Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF)**
- **[VirusTotal](https://www.virustotal.com/)**
- **[Genymotion Desktop](https://docs.genymotion.com/desktop/)**
- **[Jadx](https://github.com/skylot/jadx)**
- **[Burp Suite](https://portswigger.net/burp)**
- **[ADB (Android Debug Bridge)](https://developer.android.com/studio/command-line/adb)**
- **[Frida](https://frida.re/)**
- **[Objection](https://github.com/sensepost/objection)**
- **[Apktool](https://apktool.org/)**
- **[CyberChef](https://gchq.github.io/CyberChef/)**
- **[Kali Linux](https://www.kali.org/)**
- **[Docker](https://www.docker.com/)**
- **[VSCode](https://code.visualstudio.com/)**



## Author
Pedro Coelho  
CESAR School  
Specialization in Cybersecurity  
Mobile Application Security Course  
Instructor: Erick Nascimento