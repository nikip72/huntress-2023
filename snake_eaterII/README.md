# SnakeEaterII
## _Difficultty: Medium_
## _Category: Malware_

### _Challenge code_ (https://github.com/nikip72/huntress-2023/blob/main/snakeeater2/snake_eaterII.7z)
### _password_: infected

## Analysis

Snake Eater 2 is Windows Executable file, written in Python language and protected by PyArmor. Instead of trying to break the protection let's analyze it dynamically by running it in a brand new isolated Virtual Machine, loaded with some tools for debugging.

For initial analysis we'll use Process Monitor from Windows System Internals (https://learn.microsoft.com/en-us/sysinternals/downloads/procmon). After several executions it seems that the program chooses random folder under \Users\user\AppData\Roaming , writes the file with the flag in it and immediately deletes it. 
![](https://github.com/nikip72/huntress-2023/blob/main/snake_eaterII/ProcMon.png)
The problem to be solved is to save the contents of the file (created at a seemingly random location). There are several approaches to that:

1) Use a debugger and set a breakpoint before the deletion call
2) Try to capture the WRITE operation in an API monitor (http://www.rohitab.com/apimonitor)

Following the ApiMonitor approach after loading the binary and executing it there's a call to NtWriteFile API that has the contents of flag.txt

![](https://github.com/nikip72/huntress-2023/blob/main/snake_eaterII/ApiMon.png)


