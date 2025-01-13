import random
import logging
from capstone import CS_ARCH_X86, CS_MODE_64, CS_MODE_32

class JunkInsertion:
    """
    A pass that injects single-instruction or small-sequence junk instructions
    directly into existing blocks at random intervals, while recalculating
    addresses within the block to preserve local relative references.

    Key improvements:
      1) We avoid inserting junk after unconditional / conditional jumps or ret
         (naive 'safe' approach).
      2) We recalc intra-block addresses after insertion so that subsequent instructions
         shift by the correct number of bytes.
      3) We also patch any local (intra-block) relative_target so the same relative distance
         is preserved if it pointed to an instruction further down in the same block.
      4) We keep 'original_address' for each instruction if not set, ensuring
         the final global relocation pass can fix cross-block jumps.
    """

    def __init__(self,
                 insertion_frequency=0.3,
                 sse_junk_enabled=True,
                 max_junk_seq=3,
                 arch=CS_ARCH_X86,
                 mode=CS_MODE_64):
        """
        :param insertion_frequency: Probability of inserting junk after each instruction (0.0 -> 1.0).
        :param sse_junk_enabled: If True, we may insert SSE-based junk if SSE usage is detected.
        :param max_junk_seq: The max number of consecutive junk instructions inserted at once.
        """
        self.insertion_frequency = insertion_frequency
        self.sse_junk_enabled = sse_junk_enabled
        self.max_junk_seq = max_junk_seq
        self.arch = arch
        self.mode = mode
        self.logger = logging.getLogger(self.__class__.__name__)

    def run(self, blocks):
        """
        Main entry point: modifies the instructions in each block by
        injecting junk instructions. Then recalculates the addresses
        within each block to keep local references consistent.

        Steps:
         1) Detect SSE usage across all blocks.
         2) Insert junk instructions inside each block.
         3) Recompute addresses within each block (intra-block).
         4) Update local relative_target if it's an in-block reference.
        """
        sse_detected = self._detect_sse_usage(blocks)
        total_inserted = 0

        for block in blocks:
            inserted_count = self._insert_junk_in_block(block, sse_detected)
            total_inserted += inserted_count

            # After inserting junk, recalc addresses from top to bottom:
            self._recalc_intra_block_addresses(block)

            # Then fix local relative references (the final global fix-up is
            # still done by BlockObfuscator, but we keep block-internal jumps correct for now)
            self._fix_local_relative_refs(block)

        self.logger.debug(f"Inserted {total_inserted} junk instruction(s) across {len(blocks)} block(s).")

    # ----------------------------------------------------
    # DETECT SSE
    # ----------------------------------------------------
    def _detect_sse_usage(self, blocks):
        """
        If any instruction sets 'uses_sse_avx=True', we consider SSE usage present.
        This allows SSE-based junk if enabled.
        """
        for block in blocks:
            for ins in block.instructions:
                if ins.uses_sse_avx:
                    return True
        return False

    # ----------------------------------------------------
    # INSERT JUNK IN A SINGLE BLOCK
    # ----------------------------------------------------
    def _insert_junk_in_block(self, block, sse_detected):
        """
        Insert junk instructions into 'block' at random intervals
        (controlled by self.insertion_frequency), skipping unsafe spots.
        Returns how many total instructions were inserted.
        """
        new_instrs = []
        inserted_count = 0
        instructions = block.instructions

        for i,instr in enumerate(instructions):
            new_instrs.append(instr)

            # Look ahead: check if next instruction is a conditional instruction (and the next next, because sometime conditional instruction can be placed 2 instructions after)
            next_is_conditional_jump = (i + 1 < len(instructions) and instructions[i + 1].is_conditional)

            # Decide if we insert junk after this instruction
            # Only insert if it's safe for current instr and next isn't a conditional instruction
            if random.random() < self.insertion_frequency:
                if self._safe_to_insert_junk(instr) and not next_is_conditional_jump:
                    seq_count = random.randint(1, self.max_junk_seq)
                    junk_seq = self._generate_junk_sequence(sse_detected, seq_count)
                    new_instrs.extend(junk_seq)
                    inserted_count += len(junk_seq)

        block.instructions = new_instrs
        return inserted_count

    def _safe_to_insert_junk(self, instr):
        """
        Decide if it's safe to insert junk after 'instr'.
        We'll skip if:
          1) It's ret (block ends)
          2) It's an unconditional jump
          3) It's a conditional jump (to avoid messing with flags)
          4) It's a CMP or TEST instruction
          5) It references data
        """
        if instr.is_ret:
            return False
        if instr.is_jump and not instr.is_conditional:
            return False
        if instr.is_jump and instr.is_conditional:
            return False
        if instr.mnemonic in ["cmp", "test"]:
            return False
        if instr.is_data_reference:
            return False
        return True

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

    # ----------------------------------------------------
    # GENERATE JUNK
    # ----------------------------------------------------
    def _generate_junk_sequence(self, sse_detected, count):
        """
        Generate 'count' instructions from an expanded no-op pool.
        Some instructions might use random registers.
        If SSE is detected and enabled, we add SSE-based no-ops.
        """
        from instruction_analysis import AnalyzedInstruction

        if self.mode == CS_MODE_32:
            # 32-bit registers
            cpu_regs = ["eax", "ecx", "edx", "ebx", "esi", "edi"]
        else:
            # 64-bit registers
            cpu_regs = ["rax", "rcx", "rdx", "rbx", "rsi", "rdi", "r8", "r9", "r10", "r11"]

        xmm_regs = ["xmm0", "xmm1", "xmm2", "xmm3"]

        def nop():
            return (b"\x90", "nop", "")

        def xchg_same_reg():
            """
            Replace 'xchg reg, reg' with equivalent no-op instructions.
            For 32-bit: 'xchg reg, reg' is equivalent to 'nop' (0x90).
            For 64-bit: Use specific encodings for 'xchg reg, reg'.
            """
            if self.mode == CS_MODE_32:
                # In 32-bit, 'xchg reg, reg' is equivalent to NOP (0x90)
                raw = b"\x90"  # NOP
                reg = random.choice(cpu_regs)
                return (raw, "nop", "")  # Replace with NOP
            else:
                # 64-bit 'xchg reg, reg' has specific encodings
                xchg_map_64 = {
                    "rax": b"\x48\x87\xc0",
                    "rcx": b"\x48\x87\xc9",
                    "rdx": b"\x48\x87\xd2",
                    "rbx": b"\x48\x87\xdb",
                    "rsi": b"\x48\x87\xf6",
                    "rdi": b"\x48\x87\xff",
                    "r8": b"\x49\x87\xc0",
                    "r9": b"\x49\x87\xc9",
                    "r10": b"\x49\x87\xd2",
                    "r11": b"\x49\x87\xdb",
                }
                reg = random.choice(cpu_regs)
                raw = xchg_map_64.get(reg, b"\x48\x87\xc0")
                return (raw, "xchg", f"{reg}, {reg}")

        def mov_same_reg():
            """
            Replace 'mov reg, reg' with equivalent no-op or harmless instructions.
            """
            if self.mode == CS_MODE_32:
                # 32-bit 'mov reg, reg' opcodes
                mov_map_32 = {
                    "eax": b"\x89\xc0",  # mov eax, eax
                    "ecx": b"\x89\xc1",  # mov ecx, ecx
                    "edx": b"\x89\xc2",  # mov edx, edx
                    "ebx": b"\x89\xc3",  # mov ebx, ebx
                    "esi": b"\x89\xc6",  # mov esi, esi
                    "edi": b"\x89\xc7",  # mov edi, edi
                }
                reg = random.choice(cpu_regs)
                raw = mov_map_32.get(reg, b"\x89\xc0")
                return (raw, "mov", f"{reg}, {reg}")
            else:
                # 64-bit 'mov reg, reg' opcodes
                mov_map_64 = {
                    "rax": b"\x48\x89\xc0",
                    "rcx": b"\x48\x89\xc9",
                    "rdx": b"\x48\x89\xd2",
                    "rbx": b"\x48\x89\xdb",
                    "rsi": b"\x48\x89\xf6",
                    "rdi": b"\x48\x89\xff",
                    "r8": b"\x4c\x89\xc0",
                    "r9": b"\x4c\x89\xc9",
                    "r10": b"\x4c\x89\xd2",
                    "r11": b"\x4c\x89\xdb",
                }
                reg = random.choice(cpu_regs)
                raw = mov_map_64.get(reg, b"\x48\x89\xc0")
                return (raw, "mov", f"{reg}, {reg}")

        def sse_pxor():
            """
            Insert SSE-based no-op instructions if enabled and SSE is detected.
            """
            pxor_map = {
                "xmm0": b"\x66\x0f\xef\xc0",
                "xmm1": b"\x66\x0f\xef\xc9",
                "xmm2": b"\x66\x0f\xef\xd0",
                "xmm3": b"\x66\x0f\xef\xd9"
            }
            chosen_xmm = random.choice(xmm_regs)
            raw = pxor_map.get(chosen_xmm, b"\x66\x0f\xef\xc0")
            return (raw, "pxor", f"{chosen_xmm}, {chosen_xmm}")

        # Build the base junk pool
        base_pool = [nop, xchg_same_reg, mov_same_reg]
        if sse_detected and self.sse_junk_enabled:
            base_pool.append(sse_pxor)

        junk_instrs = []
        for _ in range(count):
            chosen_func = random.choice(base_pool)
            raw_bytes, mnemonic, op_str = chosen_func()
            ai = AnalyzedInstruction(
                address=0,  # We'll recalc soon
                size=len(raw_bytes),
                mnemonic=mnemonic,
                op_str=op_str,
                raw_bytes=raw_bytes,
                capstone_ins=None
            )
            junk_instrs.append(ai)

        return junk_instrs