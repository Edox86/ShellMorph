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
