---
layout: post
title:  "Analysis: High False Positive Sample on VirusTotal"
date:   2025-01-10
---

<p class="intro"><span class="dropcap">W</span>alk through the analysis of a sample that was flagged by a large number of antivirus engines on VirusTotal, yet turned out to be completely harmless. These kinds of high false positives are not uncommon, especially when scripts or tools used for internal automation resemble behaviors typically associated with malware.</p>

Sample can be downloaded from <a href="https://www.virustotal.com/gui/file/af5e82266c102126179d3f9ab17ff0cdd5489a315c84ae961cf998de7700fd8aVirusTotal
" target="_blank">VirusTotal</a>

**SHA256:af5e82266c102126179d3f9ab17ff0cdd5489a315c84ae961cf998de7700fd8a**

<figure>
	<img src="/assets/img/HighOnVT/VirusTotal_1.png" alt=""> 
	<figcaption>VirusTotal detections</figcaption>
</figure>

So let's get started with the analysis.

Initially, I reviewed the information (relations and behavior sections) on VirusTotal but they did not provide any significant insights.

Next, before we jump into dynamic analysis, I did some basic static analysis using FLOSS (FireEye Labs Obfuscated String Solver).
<figure>
	<img src="/assets/img/HighOnVT/FLOSS_2.png" alt=""> 
	<figcaption>FireEye Labs Obfuscated String Solver</figcaption>
</figure>

Then, while scrolling through the strings, I found some interesting clues.
{%- highlight ruby -%}
ScriptCryptor
TYPELIB\tRC_SCRIPT
%Error: %s
Line: %d
Position: %d
This application created with Unregistered version of ScriptCryptor.
Please register your copy to remove this window.
Visit http://www.abyssmedia.com for more info.
{%- endhighlight -%}

It appears that this application was created using ScriptCryptor. For your information, ScriptCryptor is a tool that converts VBS or JavaScript files into executable (EXE) files.

Let’s begin the dynamic analysis by running the program in FLARE VM. (Make sure to create a snapshot beforehand)

Upon execution, the application prompts the user to enter a username. (I translated the original prompt from Polish)
<figure>
	<img src="/assets/img/HighOnVT/LoginGUI_3.png" alt=""> 
	<figcaption>Login GUI</figcaption>
</figure>
Then, I attempted to obtain a memory dump using Process Explorer. You can do as following steps:

1. To get the memory dump, you can execute the sample first and launch the Process Explorer as admin
2. Right click on the process (the sample) and select create dump and choose Full Dump
3. Analyze the memory dump
<figure>
	<img src="/assets/img/HighOnVT/ProcExp_4.png" alt=""> 
	<figcaption>Process Explorer</figcaption>
</figure>
Once obtained the .dmp file, we can analyze using notepad++. The memory dump could be huge, so I tried to find the keywords like login, imie, podaj on any words that we see on the input box upon execution.
And this is what I found on the memory dump:
{%- highlight ruby -%}
VBScript
Set WshNetwork = WScript.CreateObject("WScript.Network")
Set clDrives = WshNetwork.EnumNetworkDrives

For i = 0 to clDrives.Count - 1
   If clDrives.Item(i) = "U:" Then
       WshNetwork.RemoveNetworkDrive "U:", True, True
   End If
   If clDrives.Item(i) = "T:" Then
       WshNetwork.RemoveNetworkDrive "T:", True, True
   End If
   If clDrives.Item(i) = "S:" Then
       WshNetwork.RemoveNetworkDrive "S:", True, True
   End If
Next

' Prompt user for login and password
slog = InputBox("Podaj login : imie.nazwisko", "Login")
sPwd = InputBox("Podaj has�o do citrixa", "Haslo")

' Map network drives
WshNetwork.MapNetworkDrive "U:", "\\10.14.3.138\PL-MG-Users\" & slog & "\userhome", False, "mg\" & slog, sPwd
WshNetwork.MapNetworkDrive "T:", "\\10.14.3.134\PL-MG-Team", False, "mg\" & slog, sPwd
WshNetwork.MapNetworkDrive "S:", "\\10.14.3.134\PL-MG-Shared", False, "mg\" & slog, sPwd

' Display completion message
MsgBox "Gotowe !!"
{%- endhighlight -%}

**Lets breakdown the script step by step:**

1. Network Drive Removal: The script first checks for the existence of three mapped network drives — U:, T: and S:

   ```ruby
   If clDrives.Item(i) = "U:" Then
       WshNetwork.RemoveNetworkDrive "U:", True, True
   End If
   ```

If any of these drives are found, they are removed using RemoveNetworkDrive. This is typically used to clear previously mapped network drives that are no longer needed or are being replaced by new mappings.

2. User Input for Login and Password: The script then prompts the user for:

   ```ruby
   Login (InputBox("Podaj login : imie.nazwisko", "Login"))
   Password (InputBox("Podaj has�o do citrixa", "Haslo")
   ```

   The use of InputBox is a straightforward way of capturing user credentials, which is fairly common in enterprise environments for connecting to network resources.

3. Mapping Network Drives: After obtaining the login and password, the script proceeds to map the following network drives:
   * U: to `\\10.14.3.138\PL-MG-Users\<username>\userhome`
   * T: to `\\10.14.3.134\PL-MG-Team`
   * S: to `\\10.14.3.134\PL-MG-Shared`

The drives are mapped to specific network shares on machines with IP addresses 10.14.3.138 and 10.14.3.134, which appear to be part of a local network. It uses the user's login (slog) and password (sPwd) to authenticate the network mapping.

In conclusion, I believe this file is benign. It appears to be a script used for automation which is not uncommon within the organization, likely to simplify the process of mapping network drives for users. However, the real question is why so many antivirus vendors on VirusTotal have flagged it as malicious. My guess is that their AI or heuristic engines may have misclassified it due to certain behaviors, such as prompting for credentials and attempting to access remote shares, which can resemble techniques used in malware.
