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
PS C:\Program Files\Microsoft Visual Studio\2022\Community> cd C:\DetonatorLab
PS C:\DetonatorLab> python.exe detlab.py loader_6 shellcode_3
Compiling: output\loader_6_shellcode_3.c into output\loader_6_shellcode_3.exe
loader_6_shellcode_3.c
```

Result in `C:\DetonatorLab\output\loader_6_shellcode_3.exe`.


## Existing Loaders

| **Loader**   | **Encryption**        | **Memory** | **Execution** | **Anti-Emulation** |
| -------- | --------------------- | ---------- | ------------- | ------------------ |
| loader_0 | \-                    | RWX        | jmp           | \-                 |
| loader_1 | multibyte-xor         | RW→RWX     | jmp           | \-                 |
| loader_2 | multibyte-xor         | RW→RWX     | jmp           | register time      |
| loader_3 | multibyte-xor         | RW→RWX     | jmp           | sirallocalot       |
|          |                       |            |               |                    |
| loader_4 | multibyte-xor patched | RW→RWX     | jmp           | \-                 |
| loader_5 | multibyte-xor patched | RW→RWX     | jmp           | register time      |
| loader_6 | multibyte-xor patched | RW→RX      | jmp           | register time      |
|          |                       |            |               |                    |
| loader_7 | multiprocess .shared |       |            |       |
| loader_8 | multiprocess dynamic mem |       |            |       |
