# reassembly.py

import logging
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_MODE_32

class Reassembler:
    r"""
    Final step: convert the final list of blocks/instructions into
    a single machine code blob by reassembling each instruction's
    textual form with Keystone, respecting the final addresses.

    Key Points:
    1) We rely on each instruction having a 'mnemonic' and 'op_str' that can
       be turned into valid assembly (e.g. "mov rax, rax"). This naive approach
       won't handle complex instructions automatically.
    2) We set each instruction's address in Keystone so that relative offsets
       (like "jmp short 0x1234") can be recalculated.
       This only works if Keystone supports 'reloc' or if we do some manual offset math.
    3) Alternatively, if you have instructions with pre-patched bytes, you might reuse 'instr.bytes'.
    4) For demonstration, we'll assume a full textual reassembly approach.
    """

    def __init__(self, arch=KS_ARCH_X86, mode=KS_MODE_64):
        self.arch = arch
        self.mode = mode
        self.logger = logging.getLogger(self.__class__.__name__)
        try:
            # If self.mode is KS_MODE_32, it will assemble 32-bit code
            self.ks = Ks(self.arch, self.mode)
        except Exception as e:
            print(f"Error initializing Keystone: {e}")
            self.ks = None

    def reassemble_final_code(self, blocks):
        """
        Takes the final obfuscated blocks (with each instruction's final address)
        and produces one contiguous blob of machine code.

        Steps:
        - Sort blocks by their start_address.
        - For each instruction in blocks, assemble it with Keystone.
        - Concatenate the bytes, filling gaps with NOPs.
        """
        if not self.ks:
            self.logger.error("Keystone not initialized, skipping reassembly.")
            return b"", 0

        if not blocks:
            return b"", 0

        # Sort blocks by start_address
        sorted_blocks = sorted(blocks, key=lambda b: b.start_address or 0)
        min_addr = min(b.start_address for b in sorted_blocks if b.start_address is not None)
        max_addr = max(ins.address + ins.size for b in sorted_blocks for ins in b.instructions if b.start_address is not None)

        # Initialize bytearray with NOPs
        final_code = bytearray([0x90] * (max_addr - min_addr))

        for block in sorted_blocks:
            for instr in block.instructions:
                if instr.address is None:
                    continue
                offset = instr.address - min_addr
                # Generate assembly line
                asm_line = self._generate_asm_line(instr)
                if asm_line:
                    try:
                        encoding, count = self.ks.asm(asm_line, addr=instr.address)
                        final_code[offset:offset+len(encoding)] = bytes(encoding)
                    except Exception as e:
                        self.logger.debug(f"Keystone asm failed for '{asm_line}' at 0x{instr.address:X}: {e}")
                        # Fallback: use existing bytes
                        final_code[offset:offset+len(instr.bytes)] = instr.bytes
                else:
                    # Use existing bytes if assembly line couldn't be generated
                    final_code[offset:offset+len(instr.bytes)] = instr.bytes

        return bytes(final_code), min_addr

    def _generate_asm_line(self, instr):
        """
        Produce a textual assembly line for Keystone.
        Example: "jmp 0x1234" or "mov rax, rax"
        """
        if instr.mnemonic == "??":
            return None

        if instr.is_relative and (instr.is_jump or instr.is_call) and instr.relative_target:
            return f"{instr.mnemonic} 0x{instr.relative_target:X}"
        else:
            if instr.op_str:
                return f"{instr.mnemonic} {instr.op_str}"
            else:
                return instr.mnemonic

    def format_as_shellcode(self, final_code):
        shellcode_str = ''.join(['\\x{:02x}'.format(b) for b in final_code])
        return shellcode_str

    def format_as_c_shellcode(self, final_code):
        shellcode_str = ''.join(['\\x{:02x}'.format(b) for b in final_code])
        return f'"{shellcode_str}"'
