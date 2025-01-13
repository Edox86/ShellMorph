# instruction_substitution.py

import logging
import random
from capstone import CS_ARCH_X86, CS_MODE_64, CS_MODE_32
from instruction_analysis import AnalyzedInstruction
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64
import sys

class InstructionSubstitutionPass:
    """
    This pass looks for 'push <immediate>' and replaces it with your requested
    sequence of 7 steps:

      1) sub esp/rsp, 0x4 or 0x8
      2) push eax/rax
      3) arithmetic in eax/rax to build the final immediate
      4) mov [esp/rsp + register_size], eax/rax
      5) pop eax/rax

    So that the newly computed value remains on the stack (in place of
    that third push), and the original registers are restored.
    """

    def __init__(self,
                 cs_arch=CS_ARCH_X86,
                 cs_mode=CS_MODE_64,
                 ks_arch=KS_ARCH_X86,
                 ks_mode=KS_MODE_64,
                 substitution_probability=1.0):
        """
        :param cs_arch: Capstone architecture constant, e.g., CS_ARCH_X86.
        :param cs_mode: Capstone mode, e.g., CS_MODE_32 or CS_MODE_64.
        :param ks_arch: Keystone architecture constant, e.g., KS_ARCH_X86.
        :param ks_mode: Keystone mode, e.g., KS_MODE_64 or KS_MODE_32.
        :param substitution_probability: 1.0 => always substitute, 0.0 => never.
        """
        self.cs_arch = cs_arch
        self.cs_mode = cs_mode
        self.ks_arch = ks_arch
        self.ks_mode = ks_mode
        self.ks = Ks(self.ks_arch, self.ks_mode)
        self.substitution_probability = substitution_probability
        self.logger = logging.getLogger(self.__class__.__name__)


    def run(self, blocks):
        """
        For each block, find recognized instructions (e.g. `push imm`, `mov reg, imm`)
        and replace them with multi-step sequences. Then recalc addresses within the block
        and fix local relative references.
        """
        total_substituted = 0

        for block in blocks:
            inserted_count = self._insert_substitution_in_block(block)
            total_substituted += inserted_count

            # After inserting junk, recalc addresses from top to bottom:
            self._recalc_intra_block_addresses(block)

            # Then fix local relative references (the final global fix-up is
            # still done by BlockObfuscator, but we keep block-internal jumps correct for now)
            self._fix_local_relative_refs(block)

        self.logger.debug(f"[InstructionSubstitutionPass] Substituted {total_substituted} push imm instructions across {len(blocks)} block(s).")


    # ----------------------------------------------------
    # SUBSTITUTION LOGIC
    # ----------------------------------------------------
    def _insert_substitution_in_block(self, block):
        """
        Iterate over instructions in 'block'.
         - If it matches `push imm`, transform (existing code).
         - If it matches `mov reg, imm`, transform (new code).
         - Otherwise, keep original.
        """
        new_instrs = []
        inserted_count = 0
        instructions = block.instructions

        for instr in instructions:
            # 1) Check for 'push imm' (EXISTING LOGIC)
            if (self._is_push_imm(instr)
                    and random.random() <= self.substitution_probability):
                imm_value = self._parse_immediate_from_push(instr)
                if imm_value is not None:
                    sub_seq = self._generate_substitution_sequence(imm_value)
                    # Let the first instruction in new_seq share original_address with the old push
                    if sub_seq:
                        sub_seq[0].original_address = instr.original_address
                    new_instrs.extend(sub_seq)
                    inserted_count += len(sub_seq)
                else:
                    new_instrs.append(instr)

            # 2) Check for 'mov reg, imm'
            elif (self._is_mov_reg_imm(instr)
                  and random.random() <= self.substitution_probability):
                parsed = self._parse_mov_reg_imm(instr)
                if parsed is not None:
                    dest_reg, imm_val = parsed
                    sub_seq = self._generate_substitution_for_mov_reg_imm(dest_reg, imm_val)
                    if sub_seq:
                        sub_seq[0].original_address = instr.original_address
                    new_instrs.extend(sub_seq)
                    inserted_count += len(sub_seq)
                else:
                    new_instrs.append(instr)

            # 3) Otherwise, try to replace single-instruction => with single-comparable-instruction
            else:
                #new_instrs.append(instr)
                if random.random() <= self.substitution_probability:
                    maybe_sub = self._try_single_instruction_substitution(instr)
                    if maybe_sub is not None:
                        # We replaced one instruction with a single instruction
                        maybe_sub.original_address = instr.original_address
                        new_instrs.append(maybe_sub)
                        inserted_count += 1
                        continue
                    else:
                        # fallback: keep original
                        new_instrs.append(instr)
                else:
                    # if no substitution occurred, keep original
                    new_instrs.append(instr)

        block.instructions = new_instrs
        return inserted_count

    # ----------------------------------------------------
    # RECOMPUTE INTRA-BLOCK ADDRESSES
    # ----------------------------------------------------
    def _recalc_intra_block_addresses(self, block):
        """
        Re-assign addresses from the first instruction onward,
        so that if we inserted new instructions (which have a certain size),
        subsequent instructions shift in address accordingly.

        We also preserve 'original_address' for each instruction if not already set.
        """
        if not block.instructions:
            return

        current_addr = block.start_address if block.start_address is not None else 0
        for idx, instr in enumerate(block.instructions):
            if not hasattr(instr, 'original_address'):
                instr.original_address = instr.address

            # assign the new address to this instruction
            instr.address = current_addr
            current_addr += instr.size

        # block's new end is the last instruction's address + size - 1
        # (the next pass in block_obfuscator will do the global relocation)

    # ----------------------------------------------------
    # FIX LOCAL RELATIVE REFERENCES
    # ----------------------------------------------------
    def _fix_local_relative_refs(self, block):
        """
        If an instruction has .relative_target that points
        to an instruction inside the SAME block, we reassign it
        to that instruction's new address. This keeps local
        jumps correct after we changed addresses.

        Global cross-block jumps remain handled by block_obfuscator's final pass.
        """
        # Build a quick map from original_address -> new_address for this block
        # We only handle instructions that belong to this block.
        local_map = {}
        for instr in block.instructions:
            if hasattr(instr, 'original_address'):
                local_map[instr.original_address] = instr.address

        for instr in block.instructions:
            if instr.is_relative and (instr.is_jump or instr.is_call):
                old_tgt = instr.relative_target
                if old_tgt is not None:
                    # If the old target is in local_map, that means the target is within the same block
                    if old_tgt in local_map:
                        new_tgt = local_map[old_tgt]
                        instr.relative_target = new_tgt
                    # else it's a cross-block target => final fix in block_obfuscator
                    # so we leave it as is
        # Done with local fix-up


    # ------------------------------------------------------------------------------
    # 1) Substitution of PUSH Imm32
    # ------------------------------------------------------------------------------

    # Identify "push imm" instructions
    def _is_push_imm(self, instr):
        """
        Checks if mnemonic is 'push' and op_str is an immediate (0x... or decimal).
        """
        if instr.mnemonic.lower() == "push":
            operand = instr.op_str.strip().lower()
            if operand.startswith("0x") or operand.isdigit():
                return True
        return False

    def _parse_immediate_from_push(self, instr):
        """
        Parse the immediate (hex or decimal) from instr.op_str.
        Return None on failure.
        """
        try:
            op_str_clean = instr.op_str.strip().lower()
            if op_str_clean.startswith("0x"):
                return int(op_str_clean, 16)
            else:
                return int(op_str_clean, 10)
        except ValueError:
            return None

    def _generate_substitution_sequence(self, imm_value):
        """
        - For x86 => use 32-bit arithmetic in EAX, split imm_value to hi/lo.
        - For x64 => use 64-bit arithmetic in RAX, split into hi32, lo32 if needed.

        Then place them into your requested sequence:
          1) sub esp/rsp, 0x4 or 0x8
          2) push eax/rax
          3) do arithmetic in eax/rax
          4) mov [esp+4]/[rsp+8], eax/rax
          5) pop eax/rax

        """
        if self.cs_mode == CS_MODE_32:
            return self._generate_substitution_x86(imm_value & 0xFFFFFFFF)
        elif self.cs_mode == CS_MODE_64:
            return self._generate_substitution_x64(imm_value & 0xFFFFFFFFFFFFFFFF)
        else:
            self.logger.warning("Unsupported mode, fallback to single push.")
            return [self._make_analyzed_ins(f"push 0x{imm_value:X}")]

    def _generate_substitution_x86(self, imm32):
        """
        5-step sequence in 32-bit, with EAX as the arithmetic register.
        We do a simple hi/lo approach:
          mov eax, hi
          add eax, lo
        Then we store the result in [esp+4].
        """
        hi = imm32 & 0xFFFF0000
        lo = imm32 & 0x0000FFFF

        sequence = []
        # 1) push eax
        sequence.append(self._make_analyzed_ins("sub esp, 0x4"))
        # 2) push eax
        sequence.append(self._make_analyzed_ins("push eax"))

        # 3) arithmetic
        if hi != 0:
            # mov eax, hi
            sequence.append(self._make_analyzed_ins(f"mov eax, 0x{hi:X}"))
            # optionally add the lo
            if lo != 0:
                sequence.append(self._make_analyzed_ins(f"add eax, 0x{lo:X}"))
        else:
            # hi == 0 => just mov eax, lo
            sequence.append(self._make_analyzed_ins(f"mov eax, 0x{lo:X}"))

        # 4) mov [esp+4], eax  (4 = register size)
        sequence.append(self._make_analyzed_ins("mov [esp+0x4], eax"))

        # 5) pop eax
        sequence.append(self._make_analyzed_ins("pop eax"))

        return sequence

    def _generate_substitution_x64(self, imm64):
        """
        5-step sequence in 64-bit, with RAX for arithmetic.
        We'll do hi32/lo32 splitting if needed:
         mov rax, hi32
         shl rax, 32
         add rax, lo32
        Then store at [rsp+24] = 8.
        """
        hi = (imm64 >> 32) & 0xFFFFFFFF
        lo = imm64 & 0xFFFFFFFF

        seq = []
        # 1) push rax
        seq.append(self._make_analyzed_ins("sub rsp, 0x8"))
        # 2) push rax
        seq.append(self._make_analyzed_ins("push rax"))

        # 3) arithmetic in RAX
        if hi != 0:
            seq.append(self._make_analyzed_ins(f"mov rax, 0x{hi:X}"))
            seq.append(self._make_analyzed_ins("shl rax, 32"))
            if lo != 0:
                seq.append(self._make_analyzed_ins(f"add rax, 0x{lo:X}"))
        else:
            # hi == 0 => just mov rax, lo
            seq.append(self._make_analyzed_ins(f"mov rax, 0x{lo:X}"))

        # 4) mov [rsp+8], rax  (8= size of a register)
        seq.append(self._make_analyzed_ins("mov [rsp+0x8], rax"))

        # 5) pop rax
        seq.append(self._make_analyzed_ins("pop rax"))

        return seq


    # ----------------------------------------------------
    # 2) SUBSTITUTIONS OF: MOV reg, imm
    # ----------------------------------------------------
    def _is_mov_reg_imm(self, instr):
        """
        Detect if the instruction is 'mov <reg>, <imm>'.
        We'll exclude memory by checking for '[' or ']'.
        """
        if instr.mnemonic.lower() == "mov" or instr.mnemonic.lower() == "movabs":
            op_str = instr.op_str.replace(" ", "").lower()
            if '[' in op_str or ']' in op_str:
                return False
            if ',' in op_str:
                parts = op_str.split(',')
                if len(parts) == 2:
                    if self._looks_like_register(parts[0]) and self._looks_like_immediate(parts[1]):
                        return True
        return False

    def _parse_mov_reg_imm(self, instr):
        """
        Parse the destination register and immediate value.
        Return (dest_reg, imm_value) or None on failure.
        """
        try:
            op_str = instr.op_str.replace(" ", "").lower()
            left, right = op_str.split(',')
            if self._looks_like_register(left) and self._looks_like_immediate(right):
                dest_reg = left
                if right.startswith("0x"):
                    imm_val = int(right, 16)
                else:
                    imm_val = int(right, 10)
                return (dest_reg, imm_val)
        except:
            pass
        return None

    def _generate_substitution_for_mov_reg_imm(self, dest_reg, imm_value):
        """
        Minimal multi-step approach that preserves EFLAGS by using pushf/popf:

        32-bit:
          pushf
          mov eax, 0x hi:00; hi/lo split and add approach
          add eax, 0x00:lo
          popf

        64-bit:
          pushf   (pushfq)
          mov rax, 0xhi:0000; hi/lo split and add approach
          add rax, 0x0000:lo
          popf    (popfq)

        This yields final stack pointer = original,
        the flags are restored, and 'dest_reg' ends up = imm_value.
        """
        if self.cs_mode == CS_MODE_32:
            return self._generate_mov_reg_imm_x86(dest_reg, imm_value & 0xFFFFFFFF)
        elif self.cs_mode == CS_MODE_64:
            return self._generate_mov_reg_imm_x64(dest_reg, imm_value & 0xFFFFFFFFFFFFFFFF)
        else:
            self.logger.warning("Unsupported mode in mov reg, imm substitution. Using direct mov.")
            return [self._make_analyzed_ins(f"mov {dest_reg}, 0x{imm_value:X}")]

    def _generate_mov_reg_imm_x86(self, dest_reg, imm32):
        """
        Obfuscated approach to load a 32-bit immediate into `dest_reg`.
        We preserve EFLAGS and the temporary register (ECX).

        Steps:
          1) pushf                ; preserve EFLAGS
          2) push ecx             ; preserve ECX
          3) xor ecx, ecx         ; zero out ECX
          4) if hi16 != 0:
               mov cx, hi16
               shl ecx, 16
          5) if lo16 != 0:
               add ecx, lo16
          6) mov dest_reg, ecx
          7) pop ecx              ; restore ECX
          8) popf                 ; restore EFLAGS

        Example: to load 0xDEADBEEF, we split:
          hi16= 0xDEAD, lo16= 0xBEEF
        """
        sequence = []

        # 1) preserve flags and ecx
        sequence.append(self._make_analyzed_ins("pushf"))
        sequence.append(self._make_analyzed_ins("push ecx"))

        # 2) Split imm32 into hi16 and lo16
        hi16 = (imm32 >> 16) & 0xFFFF
        lo16 = imm32 & 0xFFFF

        # 3) Zero out ECX (we'll build the 32-bit constant in ECX)
        sequence.append(self._make_analyzed_ins("xor ecx, ecx"))

        # 4) If the high 16 bits are nonzero, load hi16 into CX and shift
        if hi16 != 0:
            sequence.append(self._make_analyzed_ins(f"mov cx, 0x{hi16:X}"))
            sequence.append(self._make_analyzed_ins("shl ecx, 16"))

        # 5) If the low 16 bits are nonzero, add them in
        if lo16 != 0:
            sequence.append(self._make_analyzed_ins(f"add ecx, 0x{lo16:X}"))

        # 6) Move ECX => dest_reg
        sequence.append(self._make_analyzed_ins(f"mov {dest_reg}, ecx"))

        # 7) restore ecx and flags
        sequence.append(self._make_analyzed_ins("pop ecx"))
        sequence.append(self._make_analyzed_ins("popf"))

        return sequence

    def _generate_mov_reg_imm_x64(self, dest_reg, imm64):
        """
        Load a 64-bit constant into `dest_reg` in an obfuscated manner,
        preserving RFLAGS and preserving the temporary register (RCX).
        """
        sequence = []

        # 1) Preserve flags and RCX if we care about them
        sequence.append(self._make_analyzed_ins("pushf"))
        sequence.append(self._make_analyzed_ins("push rcx"))
        #sequence.append(self._make_analyzed_ins("xor rcx, rcx"))

        # 2) Split imm64 into two partial constants:
        #    High half with low bits zero, and the low bits as a separate constant.
        hi_shifted = (imm64 & 0xFFFFFFFF00000000)  # top 32 bits shifted left
        lo_32 = (imm64 & 0x00000000FFFFFFFF)

        # 3) Use movabs to load each partial.
        #    - movabs rax, hi_shifted
        #    - movabs rcx, lo_32
        #    - or rax, rcx
        sequence.append(self._make_analyzed_ins(f"movabs {dest_reg}, 0x{hi_shifted:X}"))

        # If lo_32 != 0, combine it in a register
        if lo_32 != 0:
            sequence.append(self._make_analyzed_ins(f"movabs rcx, 0x{lo_32:X}"))
            sequence.append(self._make_analyzed_ins(f"or {dest_reg}, rcx"))

        # 4) Restore RCX and flags
        sequence.append(self._make_analyzed_ins("pop rcx"))
        sequence.append(self._make_analyzed_ins("popf"))
        return sequence

    # ----------------------------------------------------
    # 3) NEW: SINGLE-INSTRUCTION => SINGLE-INSTRUCTION
    # ----------------------------------------------------
    def _try_single_instruction_substitution(self, instr):
        """
        Attempt to replace 'instr' with a single-instruction that has the same effect.
        If no match, return None. If matched, return a new AnalyzedInstruction.
        Some examples:
          - xor reg, reg -> sub reg, reg     (sets reg=0, same flags)
          - cmp reg, reg -> test reg, reg    (no reg change, same flags)
          - test reg, reg -> or reg, reg     (no reg change, same flags)

        We ONLY do this if both operands are identical registers (avoiding partial overlap).
        This yields the same behavior, including flags, so we do NOT need pushf/popf here.
        """

        # We only proceed if the instruction has exactly two operands
        # and both are the same register.
        operands = instr.op_str.replace(" ", "").split(',')
        if len(operands) != 2:
            return None
        left, right = operands[0], operands[1]
        if left != right:
            # For the transformations we do below, both regs must match
            return None

        mnemonic_lower = instr.mnemonic.lower()

        if mnemonic_lower == "xor":
            # "xor reg, reg" => "sub reg, reg"
            return self._make_single_ins_substitution("sub", left, right)

        elif mnemonic_lower == "cmp":
            # "cmp reg, reg" => "test reg, reg"
            return self._make_single_ins_substitution("test", left, right)

        elif mnemonic_lower == "test":
            # "test reg, reg" => "or reg, reg"
            return self._make_single_ins_substitution("or", left, right)

        # Add more pairs as needed
        return None

    def _make_single_ins_substitution(self, new_mnemonic, left_reg, right_reg):
        """
        Create a new single instruction 'new_mnemonic left_reg, right_reg'
        ephemeral-assemble to get approximate size, and return an AnalyzedInstruction.
        """
        asm_line = f"{new_mnemonic} {left_reg}, {right_reg}"
        new_instr = self._make_analyzed_ins(asm_line)
        return new_instr

    # ----------------------------------------------------
    # UTILITY HELPERS
    # ----------------------------------------------------
    def _looks_like_register(self, token):
        """
        Basic check if `token` is something like 'eax', 'rax', 'ecx', etc.
        Extend as needed.
        """
        possible_regs_32 = ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"]
        possible_regs_64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9",
                            "r10", "r11", "r12", "r13", "r14", "r15", "rsp", "rbp"]
        if (token in possible_regs_32) or (token in possible_regs_64):
            return True
        return False

    def _looks_like_immediate(self, token):
        """
        Check if `token` is an immediate (decimal or hex).
        """
        if token.startswith("0x"):
            try:
                int(token, 16)
                return True
            except:
                return False
        else:
            return token.isdigit()

    def _make_analyzed_ins(self, asm_line):
        """
        Create a new AnalyzedInstruction with textual mnemonic/op_str.
        raw_bytes is empty so the final reassembler can generate machine code.
        """
        parts = asm_line.strip().split(None, 1)
        mnemonic = parts[0]
        op_str = parts[1] if len(parts) > 1 else ""

        # ephemeral assembly to get a placeholder size
        asm_str = asm_line.strip()  # e.g. "mov eax, 0x1234"
        size = self._ephemeral_assemble_size(asm_str)

        # critical error! immediate termination
        if size == 0:
        #     # raise ValueError(f"Assembly instruction '{asm_line}' resulted in a size of 0.")
        #     # if you want to ensure immediate termination:
            sys.exit(f"Error: Assembly instruction '{asm_line}' resulted in a size of 0.")

        return AnalyzedInstruction(
            address=0,
            size=size,
            mnemonic=mnemonic,
            op_str=op_str,
            raw_bytes=b"",
            capstone_ins=None
        )

    # ephemeral assembly to get a more realistic size
    def _ephemeral_assemble_size(self, asm_line):
        """
        Use Keystone to assemble 'asm_line' and return len(encoding).
        On failure, return 0 as a fallback.
        """
        try:
            encoding, _ = self.ks.asm(asm_line, 0)
            return len(encoding)
        except Exception as e:
            self.logger.debug(f"Ephemeral assembly failed for '{asm_line}': {e}")
            return 0


    def lower_32bit_register(self, reg_name: str) -> str:
        """
        Convert a 64-bit register name to its 32-bit lower part.
        If not recognized, returns None (or you can return reg_name itself).
        """
        reg_map = {
            "rax": "eax",
            "rbx": "ebx",
            "rcx": "ecx",
            "rdx": "edx",
            "rsi": "esi",
            "rdi": "edi",
            "rbp": "ebp",
            "rsp": "esp",
            "r8": "r8d",
            "r9": "r9d",
            "r10": "r10d",
            "r11": "r11d",
            "r12": "r12d",
            "r13": "r13d",
            "r14": "r14d",
            "r15": "r15d",
        }
        reg_lower = reg_map.get(reg_name.lower())
        return reg_lower