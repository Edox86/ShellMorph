# disassembler.py

import capstone
import sys

class Disassembler:
    def __init__(self, arch=capstone.CS_ARCH_X86, mode=capstone.CS_MODE_64):
        """
        Initialize Capstone disassembler with specified architecture and mode.

        Parameters:
        - arch (capstone.CS_ARCH_*): The architecture to disassemble.
        - mode (capstone.CS_MODE_*): The mode of the architecture.

        Example Usages:
        - x86_64: arch=capstone.CS_ARCH_X86, mode=capstone.CS_MODE_64
        - x86_32: arch=capstone.CS_ARCH_X86, mode=capstone.CS_MODE_32
        - ARM: arch=capstone.CS_ARCH_ARM, mode=capstone.CS_MODE_ARM
        - ARM64: arch=capstone.CS_ARCH_ARM64, mode=capstone.CS_MODE_ARM
        """
        self.arch = arch
        self.mode = mode
        try:
            self.cs = capstone.Cs(self.arch, self.mode)
            self.cs.detail = True
        except capstone.CsError as e:
            print(f"Error initializing Capstone: {e}")
            sys.exit(1)

    def disassemble_shellcode(self, shellcode, base_address=0x1000):
        """
        Disassemble the given shellcode bytes from 'base_address'.

        Parameters:
        - shellcode (bytes): The raw shellcode bytes to disassemble.
        - base_address (int): The starting address for disassembly.

        Returns:
        - List[dict]: A list of dictionaries containing instruction details.
        """
        instructions = []
        for ins in self.cs.disasm(shellcode, base_address):
            instr = {
                'address': ins.address,
                'size': ins.size,
                'mnemonic': ins.mnemonic,
                'op_str': ins.op_str,
                'bytes': bytes(ins.bytes),  # raw bytes
                'instruction': ins  # Store the original Capstone instruction object for further use
            }
            instructions.append(instr)

        return instructions

    def print_instructions(self, instructions):
        """
        Print a list of instructions in a readable format.

        Parameters:
        - instructions (List[dict]): The list of instructions to print.
        """
        for instr in instructions:
            print("0x{:X}: {:<10} {}".format(
                instr['address'],
                instr['mnemonic'],
                instr['op_str'])
            )
def test():
    """
    Quick self-test with sample shellcode for different architectures.
    """
    # Sample x86_64 shellcode: xor rax, rax; ret
    sample_shellcode_x64 = b"\x48\x31\xc0\xc3"

    # Sample x86_32 shellcode: xor eax, eax; ret
    sample_shellcode_x86 = b"\x31\xc0\xc3"

    # Sample ARM shellcode: mov r0, #0; bx lr
    sample_shellcode_ARM = b"\x00\x00\xa0\xe3\x1E\xFF\x2F\xE1"

    # Sample ARM64 shellcode: mov x0, #0; ret
    sample_shellcode_ARM64 = b"\x00\x00\x80\xd2\xc0\x03\x5F\xD6"

    print("=== Disassembling x86_64 Shellcode ===")
    disasm_x64 = Disassembler(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    ins_list_x64 = disasm_x64.disassemble_shellcode(sample_shellcode_x64, 0x1000)
    disasm_x64.print_instructions(ins_list_x64)
    print()

    print("=== Disassembling x86_32 Shellcode ===")
    disasm_x86 = Disassembler(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    ins_list_x86 = disasm_x86.disassemble_shellcode(sample_shellcode_x86, 0x1000)
    disasm_x86.print_instructions(ins_list_x86)
    print()

    print("=== Disassembling ARM Shellcode ===")
    disasm_ARM = Disassembler(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    ins_list_ARM = disasm_ARM.disassemble_shellcode(sample_shellcode_ARM, 0x1000)
    disasm_ARM.print_instructions(ins_list_ARM)
    print()

    print("=== Disassembling ARM64 Shellcode ===")
    disasm_ARM64 = Disassembler(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    ins_list_ARM64 = disasm_ARM64.disassemble_shellcode(sample_shellcode_ARM64, 0x1000)
    disasm_ARM64.print_instructions(ins_list_ARM64)
    print()

if __name__ == "__main__":
    test()
