# ShellMorph

## Overview
ShellMorph is a Python 3 project designed to manipulate and obfuscate shellcode for various use cases. This tool allows users to disassemble, analyze, and modify shellcode with advanced techniques, including instruction substitution, junk insertion, block reordering, and more.

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
3. Expand instruction substitutions with additional safe options.
4. Add support for code flattening.

---

## Contributing

Contributions are welcome! If you encounter any issues or have feature requests, feel free to open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

