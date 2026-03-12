# Detecting Unmanaged PowerShell and C# Injection

## Objective
This folder contains a hands-on walk-through of simulating and detecting the injection of managed code (PowerShell/C#) into an unmanaged, native Windows process. The goal is to successfully inject a payload into the Windows Print Spooler service (`spoolsv.exe`) to evade standard execution logging, and then use memory analysis and telemetry to hunt down the primary Indicator of Compromise (IOC): the unexpected loading of the .NET Common Language Runtime (`clr.dll`).

## Tools & Prerequisites
* **OS:** Windows VM
* **Monitoring/Analysis:** Process Hacker, System Telemetry (e.g., Sysmon)
* **Target Binary:** Windows Print Spooler (`spoolsv.exe` running as `NT AUTHORITY\SYSTEM`)
* **Payload/Tool:** PowerSploit module `Invoke-PSInject.ps1`

---

## Phase 1: Executing the Injection
Native Windows services like `spoolsv.exe`, `lsass.exe`, and `svchost.exe` are written in C/C++ and are inherently **unmanaged**. They do not require the .NET framework to run. Attackers target these processes because they often run with high privileges and allow malicious code to hide within legitimate system traffic.

To simulate the attack, I used `Invoke-PSInject` to execute a base64-encoded PowerShell payload directly into the memory space of `spoolsv.exe`.

1. Identified the Process ID (PID) of `spoolsv.exe` (in this case, PID `2380`).
2. Executed the PowerSploit script to inject the payload.

![Injection Execution](images/Screenshot%202026-03-11%20115105.png)
*(Image: Executing Invoke-PSInject -ProcId 2380 with the encoded payload)*

---

## Phase 2: Analyzing Process Memory (The "Managed" Smoking Gun)
Once the payload is injected into an unmanaged process, that process is forced to load the .NET runtime to execute the C# or PowerShell code. This behavior is highly anomalous and serves as our primary detection mechanism.

Using Process Hacker, I inspected the `spoolsv.exe` process post-injection. 

![Process Hacker Managed Flag](images/Screenshot%202026-03-11%20193116.png)
*(Image: Process Hacker confirming that spoolsv.exe is now flagged as a "managed (.NET)" process)*

Digging deeper into the memory map of the process, we can clearly see that `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll` has been loaded into memory. A normal instance of the Print Spooler service should never load this DLL.

![Memory Map clr.dll](images/Screenshot%202026-03-11%20113205.png)
*(Image: Memory map showing the base address and size of the loaded clr.dll module)*

---

## Phase 3: Hunting for IOCs with Telemetry
To detect this technique at scale within an enterprise environment, we rely on telemetry that monitors anomalous module loads, such as Sysmon Event ID 7 (Image Loaded).

Looking at the telemetry logs during the time of the attack, we can capture the exact moment the .NET runtime is injected into the spooler service.

![Telemetry clr.dll Load](images/Screenshot%202026-03-11%20120216.png)
*(Image: Telemetry showing clr.dll explicitly loading into spoolsv.exe running as SYSTEM)*

### Detection Logic 
By establishing a baseline, we know that native Windows binaries should not load `clr.dll` or `mscoree.dll`. We can build robust detection rules (like a Sysmon query) based on this anomaly:

```sql
EventID = 7 
AND 
(ImageLoaded ENDS WITH "clr.dll" OR ImageLoaded ENDS WITH "mscoree.dll") 
AND 
Image IN (
    "C:\Windows\System32\spoolsv.exe", 
    "C:\Windows\System32\lsass.exe", 
    "C:\Windows\System32\svchost.exe", 
    "C:\Windows\System32\cmd.exe"
)
```

Conclusion
This exercise highlights the forensic footprint left behind by in-memory execution techniques. While injecting into unmanaged processes can successfully bypass traditional antivirus file scanning and process-execution logging (Event ID 1), it creates a loud anomaly in process memory. By monitoring for unexpected .NET runtime module loads (clr.dll), defenders can effectively hunt for and detect advanced evasion techniques like PowerShell and C# injection.

