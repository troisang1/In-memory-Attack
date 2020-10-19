# In-memory Attack

## ShellCode_64
#### Feature
- 1 - CreateThread                               --- run shellcode in local process
- 2 - ApcQueueCodeInjectionAndNtTestAlert        --- run shellcode in local process
- 3 - ShellcodeExecutionViaFibers                --- run shellcode in local process
- 4 - ShellcodeExecutionViaCreateThreadpoolWait  --- run shellcode in local process
- 5 - WindowsAPIHooking                          --- run shellcode in local process
- 6 - ImportAdressTableHooking                   --- run shellcode in local process
- 7 - LocalShellcodeExecutionWithoutVirtualAlloc --- run shellcode in local process

## ShellCode_64_Remote
#### Feature
- 1 - CreateRemoteThread                                    --- inject shellcode into a "notepad" process (create new if not found) 
- 2 - ApcQueueCodeInjection                                 --- inject shellcode into a "firefox.exe" process (Can be fail because no thread at alertable state)
- 3 - EarlyBirdApcQueueCodeInjection                        --- inject shellcode into a NEW "notepad" process
- 4 - InjectingRemoteProcessViaThreadHijacking              --- inject shellcode into a "notepad" process (create new if not found) --- NOT stable 
- 5 - AddressOfEntryPointCodeInjectionWithoutVirtualAlloc   --- inject shellcode into a NEW "notepad" process (some payload with -b option fail)
- 6 - ImportAdressTableHooking                              --- inject shellcode into a NEW "notepad" process (DEACTIVE)
- 7 - ShareMemoryInjection                                  --- inject shellcode into a NEW "notepad" process
- 8 - ForciblyMapASectionWritePrimitive                     --- inject shellcode into a NEW "notepad" process


#### Using
- Input must follow format: -f *shellcode_file_path* -t *option*
  - *option*            --- 1->8 correspond to Feature
  - *shellcode_file*    --- raw,txt file


## Dll_Injection 
#### Feature
- 1 - CreateThread                                          --- inject a dll into another process and exec it
- 2 - WindowsAPIHooking                                     --- inject a dll into another process and exec it
- 3 - InjectingRemoteProcessViaThreadHijacking              --- inject a dll into another process and exec it
- 4 - ReflectiveDLLInjection                                --- inject a dll into itself and exec it
- 5 - EarlyBirdApcQueueDllInjection                         --- inject a dll into another process and exec it


#### Using
- Input must follow format:  *dll_file_path* *option*
  - *option*            --- 1->5 correspond to Feature

## Malicious DLL
#### Using
- This is demo version so that to use this, you have to hardcode *shellcode path* in source code and recompile dll