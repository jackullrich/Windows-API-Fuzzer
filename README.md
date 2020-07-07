# Windows-API-Fuzzer
Designed to learn OS specific anti-emulation patterns by fuzzing the Windows API.


#Example usage

Truffle needs a DLL, searched first using GetModuleHandle, then LoadLibrary, to perform analysis on.
Truffle will execute arbitrary code, please run ONLY in a VM!
To adjust the timeout of a function, specify the timeout (-t) in ms.

truffle.exe -dll crypt32.dll 
truffle.exe -dll crypt32.dll -t 6000

#More information

https://winternl.com/fuzzing-the-windows-api-for-av-evasion/
https://github.com/SPTHvx/SPTH/blob/master/articles/files/dynamic_anti_emulation.txt
