# HITCON 2023 Demo CVE-2023-20562

## Description
This demonstration took place at HITCON 2023 in Taiwan. The demo highlights the exploitation of AMDCpuProfiler.sys within AMD μProf. By triggering an arbitrary write on the EPROCESS token, privilege escalation to SYSTEM level is achieved. Disabling the DSE flag allows loading of a malicious unsigned driver. The presentation further showcases an attack on 360 Total Security through nullifying its ObRegisterCallbacks, enabling execution of malicious actions on the processes of 360 Total Security.

## Info
* Topic: Uncovering Kernel Exploits: Exploring Vulnerabilities in AMD's Windows Kernel Drivers
* Session: https://hitcon.org/2023/CMT/en/agenda/5cb8168d-8fd6-4741-95a5-2e32aeb3e8af/
* Slide: https://drive.google.com/file/d/1bWwzsUL0aSQA3lqu1WFrtAp3EW93Y0cx/view?usp=sharing
* Demo Video: https://youtu.be/j8dpt3TLKKY

## Environment
* Windows 10 1909
* Visual Studio 2017
* AMD μProf 3.6.839
* 360 Total Security 6.6.0.1060

## Usage
1. Install AMD μProf 3.6.839 and 360 Total Security 6.6.0.1060
2. Put exploit.exe and Malicious.sys to the same directory.
3. Execute `exploit.exe LPE` with a normal user, and a cmd.exe with SYSTEM privilege is expected to pop up.
4. Execute `exploit.exe BYOVD` in the cmd.exe with SYSTEM privilege, and the processes of 360 Total Security are expected to be killed.

Note that since the DSE flag is not reset to the original value, and the callbacks is forcelly nullified, the system may not be stable.

## Reference
* nt!_SEP_TOKEN_PRIVILEGES - Single Write EoP Protect: https://anti-reversing.com/Downloads/Sec_Research/ntoskrnl_v10.0.15063_nt!_SEP_TOKEN_PRIVILEGES-Single_Write_EoP_Protect.pdf
* EXPLOITING VIR.IT EXPLORER ANTI-VIRUS ARBITRARY WRITE VULNERABILITY: https://www.greyhathacker.net/?p=990
* find DSE flag: https://github.com/hfiref0x/DSEFix