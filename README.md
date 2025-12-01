# DetonatorLab

Detonator experiments.


## Usage

```
> python.exe .\detlab.py              
Usage: python detlab.py <loader> <shellcode> 
```

* **Loader**: one of `loader/`
* **Shellcode**: one of `shellcode/`

```
**********************************************************************
** Visual Studio 2022 Developer PowerShell v17.12.4
** Copyright (c) 2022 Microsoft Corporation
**********************************************************************

PS C:\DetonatorLab> python.exe detlab.py loader_6 shellcode_3
Compiling: output\loader_6_shellcode_3.c into output\loader_6_shellcode_3.exe
loader_6_shellcode_3.c
```

Result in `C:\DetonatorLab\output\loader_6_shellcode_3.exe`.


## Existing Loaders

| **Loader**    | **Payload Location** | **Encryption**           | **Memory** | **Execution** | **Anti-Emulation** | **Output** |
|---------------|----------------------|--------------------------|------------|---------------|--------------------|------------|
| loader_0      | .data                | \-                       | RWX        | jmp           | \-                 | exe        |
| loader_1      | .data                | multibyte-xor            | RW→RWX     | jmp           | \-                 | exe        |
| loader_2      | .data                | multibyte-xor            | RW→RWX     | jmp           | register time      | exe        |
| loader_3      | .data                | multibyte-xor            | RW→RWX     | jmp           | sirallocalot       | exe        |
|               |                      |                          |            |               |                    |            |
| loader_4      | .data                | multibyte-xor patched    | RW→RWX     | jmp           | \-                 | exe        |
| loader_5      | .data                | multibyte-xor patched    | RW→RWX     | jmp           | register time      | exe        |
| loader_5a     | .rsrc                | multibyte-xor patched    | RW→RWX     | jmp           | register time      | exe        |
| loader_5a_dll | .rsrc                | multibyte-xor patched    | RW→RWX     | jmp           | register time      | dll        |
| loader_6      | .data                | multibyte-xor patched    | RW→RX      | jmp           | register time      | exe        |
|               |                      |                          |            |               |                    |            |
| loader_10     |                      | multiprocess .shared     |            |               |                    | exe        |
| loader_11     |                      | multiprocess dynamic mem |            |               |                    | exe        |
