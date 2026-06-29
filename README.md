# Analysis of a Cobalt Strike Beacon (2021.exe)

This sample was downloaded from vx-underground, and it was analyzed knowing it was part of the Cobalt Strike family. It’s a C2 beacon written in C for the Windows OS x86-64 architecture. It’s primary function is to repetitively reach out to it’s home server in an attempt to download further malware payloads. 

![Exe Information](Screenshots/PE_info.png)

## Basic Static Analysis

![SHA256sum](screenshots/SHA.png)
![VirusTotal Results](screenshots/VT_results.png)

FLOSS shows multiple architecture-specific runtime library files. Early indication that this exe is written in C and will call low-level system operations. Multiple C files in strings as well.

![FLOSS CRT Files](screenshots/floss_C_runtime_files.png)
![FLOSS C Files and Operations](screenshots/floss_C_files_and_operations.png)

There’s also a repeated pattern in the strings output with GUID_ that define the specific action to be taken by the OS. For example, we see power button behavior, battery discharges, sleep actions, and standby state. 

![Repeated Patterns](screenshots/floss_repeated_pattern.png)

Seven flagged Win API imports in PEStudio, all under the kernel32.dll library:

GetCurrentProcess
GetcurrentProcessId
GetCurrentThreadId
RtlAddFunctionTable
VirtualAlloc
VirtualProtect
VirtualQuery 

![PEStudio Win API Imports](screenshots/pestudio_imports.png)

## Basic Dynamic Analysis

With REMnux inetsim turned off, initial execution of the malware doesn’t show any immediate actions, pop ups, file writes, etc. All we see is the cursor spinning. The same happens when we turn inetsim on and re-execute the bin.

![Initial Execution](screenshots/initial_execution.png)

With inetsim on and Wireshark running, execution of the bin shows outbound DNS calls to service-jfm40pz6-1305872363[.]gz[.]apigw[.]tencentcs[.]com

![Repeated Patterns](screenshots/wireshark_c2_domain.png)

Procmon shows the Registry key for cryptography is accessed, and then the UDP send and receive for the DNS request immediately follows. After that we see fwpuclnt.dll and mswsock.dll opened. This indicates the bin is attempting to establish an encrypted C2 comm. 

![Attempted C2 Comms](screenshots/c2_comms_attempted_establish.png)

There is then a long string of TCP Reconnect and Disconnects across sequential ports 50164, 50165, 50166…to 50173 before the bin creates the werfault.exe process and exits the thread. 

![TCP and Werfault.exe](screenshots/TCP_and_werfault.png)

This is likely the beacon killing itself since a connection cannot be successfully established. The PPID also changes every time the bin is executed, which indicates it’s spawning child processes. In this case, it’s spawning a child of itself with the same name (2021[.]exe) and werfault. 

![Child Process](screenshots/child_process.png)

While the 2021[.]exe parent is starting everything, werfault is doing the heavy lifting. Closer analysis shows thousands of Registry operations, file creation and modification events, and thread creation and exits:

![Werfault Registry Operations](screenshots/werfault_reg.png)

![Werfault Thread Operations](screenshots/werfault_threads.png)

There are 851 WriteFile events where crash reports are being written to the following directories: 

C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...
C:\ProgramData\Microsoft\Windows\WER\Temp…

These reports are relatively basic and just confirming what we already know. The bin attempted to perform its communication, and when it couldn’t it killed itself and werfault documented it. 

However, the Registry operations are still highly abnormal as werfault doesn’t perform these. This behavior indicates the bin is injecting itself into werfault to evade detection. It also means we might be able to carve something from memory when performing our advanced analysis.

TCPView confirms the injection as we see 2021.exe initially attempt to make outbound comms, followed closely by werfault and wermgr. 

![TCPView 1](screenshots/tcpview_first_connection.png)
![TCPView 2](screenshots/tcpview_wermgr.png)
![TCPView 3](screenshots/tcpview_wermgr_2.png)

It should be noted that werfault initially spawns wermgr in this situation, and wermgr is observed sequentially cycling through local ports to establish a connection. When it cannot, it kills itself. 

## Advanced Static Analysis

Loaded into Cutter and identified fcn.00401560 as the main function, and renamed it. When examining the first part of main, we see function 00401710 being called right before sub.msvcrt.dll_clock. This is followed by some mov operations, one of which is qword [Sleep] and then another call to sub.msvcrt.dll_clock.

![Cutter Main Function](screenshots/cutter_main_function_id.png)
![Cutter Main Function Renamed](screenshots/main_function.png)

Looking at the decompiled code shows fcn_00401710 being called, which is the benign C runtime exit-handler setup. Then the bin is getting into a basic anti sandbox check, where it expects some minimum CPU time to have passed between the two clock calls. 

So, if our sample is running too fast in an emulated environment, or it detects tools, the program kills itself early. If it passes these checks, the decryption loop for the actual core stager payload. You can see it with the looped XOR decryption of an embedded blob: 

![XOR Loop](screenshots/xor_loop.png)

After this XOR loop, executable memory is allocated and the payload is copied into it. This is a textbook dll injection and shellcode execution. The next step will be to attempt to set a breakpoint before the memcpy call (0x00402bf0) and attempt to dump the memory at the VirtualAlloc return address.

Here’s the full decompiled code:

![Decompiled Main](screenshots/decompiled_main.png)

## Advanced Dynamic Analysis

The goal here is to find the carve out the payload from memory. We have our locations from Cutter under 00x00401607, where VirtualAlloc is moved into rax, and then rax is called. A few lines later, sub.msvcrt.dll_memcpy is called. These are our targets: 

0x0040161d (move VirtualAlloc to rax)
0x00401624 (call rax)
0x00401643 (call memcpy)

![Memory Locations](screenshots/virtualalloc_and_memcpy_locations.png)

So, we take the locations from Cutter, find them in x64dbg, and put our breakpoint immediately after the call for memcpy. The goal is to attempt to carve the shellcode holding the beacon information from memory.

![x64dbg Breakpoints](screenshots/breakpoints_in_x64.png)

Once we get to that point in execution, we dump the memory data into a bin file and attempt to carve with scdbg. Unfortunately, the attempt was unsuccessful:

![Shellcode Carve](screenshots/carve_shellcode_unsuccessful.png)

At this point, we pivoted as the content may have been encrypted. An attempt was made to decrypt via some Python scripts and then the decrypted dump using specific Cobalt Strike parsing tools, like csce. Again, frustratingly, this effort was unsuccessful:

![Decrypted Beacon Python](screenshots/decrypt_py_1.png)
![Carved Beacon DLL](screenshots/decrypt_py_2.png)
![Python Script Execution](screenshots/python_script_execution.png)
![csce Output](screenshots/attempted_csce.png)

Admittedly, this is about as far as my knowledge and learning will take me on this one. 

But for one final step, we are able to effectively establish C2 comms by altering the hosts file on the machine. 

![Hostfile Modification](screenshots/etc_modification.png)
![Netcat Connection](screenshots/nc_connection_shell_success.png)

The commands were not being recognized, so we built a simple Python listener that had slightly more functionality that netcat and attmped to run commands that way. 

![Python Listener](screenshots/python_listener_attempt.png)

Despite attempting to run commands, both shells would not communicate them to the FLARE vm. This is somewhat expected as Cobalt Strike beacons don’t function as typical reverse shells. They are specifically looking for a handshake performed via an encrypted protocol. So, the GET was a success but the commands themselves were not.

## YARA Rule

rule Cobalt Strike Beacon—2021.exe {
   
    meta:
        description = "Cobalt Strike Beacon—2021.exe"
        author = "Will Schmidt"
        date = "6-26-26"
        hash = "942a315f52b49601cb8a2080fa318268f7a670194f9c5be108d936db32affd52"
        reference = "service-jfm40pz6-1305872363.gz.apigw.tencentcs.com"


    strings:
        // MZ check
        $PE_magic_byte = "MZ"


        // C2 domain found in sample
        $c2domain = "service-jfm40pz6-1305872363.gz.apigw.tencentcs.com" ascii fullword
       
        // Potential Tencent domain variations
        $variant1 = "apigw.tencentcs.com" ascii
        $variant2 = ".gz.apigw.tencentcs.com" ascii
       
        // Size of the encrypted blob (0x551E5)
        $size1 = { 55 1E 05 }    
        $size2 = { 00 05 51 E5 }  


        // Reflective loading signatures
        $reflect1 = "VirtualAlloc" ascii
        $reflect2 = "memcpy" ascii
       
        // User Agent and Booststrap Pattern
        $useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0" ascii
        $path = "/bootstrap-2.min.js" ascii


    condition:
        $PE_magic_byte at 0 and
        (
            $c2 or
            (1 of ($variant*)) or
            (1 of ($size*)) or
            (all of ($reflect*)) or
            ($ua and $path)
        )
}
