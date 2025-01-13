import random
import logging
import struct

class BlockObfuscator:
    """
    A class to reorder, relocate, and optionally insert junk blocks in a code flow
    built from BasicBlock objects. It also fixes all relative offsets in x86/x64 code,
    performing iterative upgrades from short to near jumps if needed.
    """

    def __init__(self,
                 base_address=0x400000,
                 block_alignment=0x10,
                 insert_junk_blocks=False,
                 junk_block_count=2,
                 reorder_strategy="advanced-cfg",
                 preserve_entry=True):
        """
        :param base_address: Address where we place the first block.
        :param block_alignment: Alignment for each block start (1, 16, etc.).
        :param insert_junk_blocks: If True, add random junk blocks for obfuscation.
        :param junk_block_count: How many junk blocks to create.
        :param reorder_strategy: Strategy for reordering blocks.
               "simple-random": keep block[0] as entry, shuffle the rest.
               "advanced-cfg": use a graph-based approach to reorder.
        :param preserve_entry: If True, ensure the first block in the final
               sequence is the original entry block (blocks[0]) or whichever block
               has no incoming edges.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.base_address = base_address
        self.block_alignment = block_alignment
        self.insert_junk_blocks = insert_junk_blocks
        self.junk_block_count = junk_block_count
        self.reorder_strategy = reorder_strategy
        self.preserve_entry = preserve_entry

    def obfuscate(self, blocks):
        """
        Main entry point to obfuscate a list of BasicBlocks:
          1) Insert junk blocks (optional)
          2) Reorder blocks (using the chosen strategy)
          3) Iteratively relocate blocks + fix relative offsets
             until no more changes in instruction sizes/addresses occur.

        Return the final list of blocks in the new order.
        """
        if not blocks:
            return blocks

        # 1) Optionally insert junk blocks
        if self.insert_junk_blocks:
            self._insert_junk_blocks(blocks)

        # 2) Reorder blocks
        new_order = self._do_reorder(blocks)

        # 3) Iterative fix: relocate + fix offsets until stable
        self._iterative_fix_jumps(new_order)

        return new_order

    # ------------------------------------------------------------------
    # 1) Insert Junk Blocks (example)
    # ------------------------------------------------------------------
    def _insert_junk_blocks(self, blocks):
        from block_builder import BasicBlock
        from instruction_analysis import AnalyzedInstruction

        existing_count = len(blocks)
        positions = random.sample(
            range(existing_count+1),
            min(self.junk_block_count, existing_count+1)
        )

        for i, pos in enumerate(positions):
            b_junk = BasicBlock(block_id=10000 + i)
            # Insert 2 NOP instructions, for example
            nop1 = AnalyzedInstruction(
                address=0, size=1, mnemonic="nop", op_str="", raw_bytes=b"\x90", capstone_ins=None
            )
            nop2 = AnalyzedInstruction(
                address=1, size=1, mnemonic="nop", op_str="", raw_bytes=b"\x90", capstone_ins=None
            )
            b_junk.instructions.append(nop1)
            b_junk.instructions.append(nop2)
            blocks.insert(pos, b_junk)

        self.logger.debug(f"Inserted {len(positions)} junk block(s).")

    # ------------------------------------------------------------------
    # 2) Reorder Blocks
    # ------------------------------------------------------------------
    def _do_reorder(self, blocks):
        if self.reorder_strategy == "simple-random":
            return self._simple_random_reorder(blocks)
        elif self.reorder_strategy == "advanced-cfg":
            return self._advanced_cfg_reorder(blocks)
        else:
            self.logger.warning(f"Unknown reorder strategy {self.reorder_strategy}, using simple-random.")
            return self._simple_random_reorder(blocks)

    def _simple_random_reorder(self, blocks):
        if len(blocks) < 2:
            return blocks
        if self.preserve_entry:
            first = blocks[0]
            tail = blocks[1:]
            random.shuffle(tail)
            return [first] + tail
        else:
            bcopy = blocks[:]
            random.shuffle(bcopy)
            return bcopy

    def _advanced_cfg_reorder(self, blocks):
        # Example pseudo-topological random reorder
        reverse_edges = self._compute_reverse_edges(blocks)
        entry_blocks = self._find_entry_blocks(blocks, reverse_edges)
        visited = set()
        final_order = []

        if self.preserve_entry and blocks[0] in entry_blocks:
            forced = [blocks[0]]
            others = [b for b in entry_blocks if b != blocks[0]]
            random.shuffle(others)
            entry_seq = forced + others
        else:
            entry_seq = list(entry_blocks)
            random.shuffle(entry_seq)

        for root in entry_seq:
            if root not in visited:
                self._randomized_dfs(root, visited, final_order)

        leftover = [b for b in blocks if b not in visited]
        random.shuffle(leftover)
        for b in leftover:
            self._randomized_dfs(b, visited, final_order)

        return final_order

    def _compute_reverse_edges(self, blocks):
        rev = {b: set() for b in blocks}
        for b in blocks:
            for s in b.successors:
                rev[s].add(b)
        return rev

    def _find_entry_blocks(self, blocks, reverse_edges):
        entries = [b for b in blocks if len(reverse_edges[b]) == 0]
        if not entries:
            entries = [blocks[0]]
        return entries

    def _randomized_dfs(self, block, visited, final_order):
        stack = [block]
        while stack:
            curr = stack.pop()
            if curr not in visited:
                visited.add(curr)
                final_order.append(curr)
                succs = list(curr.successors)
                random.shuffle(succs)
                stack.extend(succs[::-1])

    # ------------------------------------------------------------------
    # 3) Iterative Fixing of Jumps
    # ------------------------------------------------------------------
    def _iterative_fix_jumps(self, blocks, max_iterations=10):
        """
        An iterative approach:
        1) Relocate all blocks
        2) Build a map of original->new addresses
        3) Attempt to fix each relative instruction, upgrading short to near if needed,
           which may change instruction sizes.
        4) If any size changed, we do another iteration, up to max_iterations.

        After it stabilizes (no size changes in a full pass), we are done.
        """
        iteration_count = 0
        while iteration_count < max_iterations:
            iteration_count += 1
            self.logger.debug(f"Fix iteration {iteration_count}")

            # (a) relocate blocks
            self._relocate_blocks(blocks)

            # (b) build address map
            addr_map = {}
            for b in blocks:
                for ins in b.instructions:
                    if not hasattr(ins, 'original_address'):
                        ins.original_address = ins.address
                    addr_map[ins.original_address] = ins.address

            # (c) fix all instructions; track if we changed any sizes
            changed_any_size = self._fix_all_relative_offsets(blocks, addr_map)

            if not changed_any_size:
                # stable => done
                self.logger.debug("No more size changes; iteration stable.")
                break

        else:
            self.logger.warning(f"Reached max_iterations={max_iterations} without stable fix.")

    def _relocate_blocks(self, blocks):
        """
        Simple approach: each block is placed sequentially at base_address + block_alignment as needed.
        We recalc each instruction's address by applying the offset from the block's old start.
        """
        current_addr = self.base_address
        for block in blocks:
            aligned_addr = self._align_address(current_addr, self.block_alignment)
            delta = aligned_addr - (block.start_address if block.start_address else aligned_addr)
            for ins in block.instructions:
                old_addr = ins.address
                new_addr = old_addr + delta
                ins.address = new_addr
            if block.instructions:
                block.start_address = block.instructions[0].address

            size = self._compute_block_size(block)
            current_addr = block.start_address + size

    def _compute_block_size(self, block):
        if not block.instructions:
            return 0
        first = block.instructions[0].address
        last = block.instructions[-1]
        return (last.address + last.size) - first

    def _align_address(self, addr, alignment):
        if alignment <= 1:
            return addr
        remainder = addr % alignment
        if remainder != 0:
            addr += (alignment - remainder)
        return addr

    # ------------------------------------------------------------------
    # 4) _fix_all_relative_offsets: Patch short/near/far as needed
    # ------------------------------------------------------------------
    def _fix_all_relative_offsets(self, blocks, addr_map):
        """
        Returns True if we changed any instruction's size (e.g. short->near upgrade).
        Otherwise False.
        """
        changed_size = False

        for block in blocks:
            for ins in block.instructions:
                if ins.is_relative and (ins.is_jump or ins.is_call):
                    old_tgt = ins.relative_target
                    if old_tgt is not None:
                        new_tgt = addr_map.get(old_tgt)
                        if new_tgt is not None:
                            # Patch + possibly upgrade the instruction if out-of-range
                            did_change = self._patch_relative_and_maybe_upgrade(ins, new_tgt)
                            if did_change:
                                changed_size = True
                        else:
                            self.logger.debug(f"No new address for old target {old_tgt:X}, skip patch.")
        return changed_size

    def _patch_relative_and_maybe_upgrade(self, instr, new_target):
        """
        1) Compute displacement = new_target - (instr.address + instr.size).
        2) If it's out of range for short jump, upgrade to near (or far).
        3) Rebuild instr.bytes with new opcode, displacement.
        4) If instr.size changed, return True; else False.
        """
        displacement = new_target - (instr.address + instr.size)
        old_size = instr.size
        old_bytes = instr.bytes

        if len(old_bytes) < 1:
            return False  # no change

        opcode = old_bytes[0]
        if opcode == 0xEB:
            # short jmp (rel8)
            if self._in_short_range(displacement):
                self._patch_short_jump(instr, displacement)
            else:
                # upgrade to near jmp
                self._upgrade_to_near_jmp(instr, displacement)

        elif 0x70 <= opcode <= 0x7F:
            # short conditional
            if self._in_short_range(displacement):
                self._patch_short_jump(instr, displacement)
            else:
                self._upgrade_to_near_cond(instr, displacement)

        elif opcode in (0xE8, 0xE9):
            # near call/jmp
            # if you want to handle 'far' you can do it here, but typically shellcode doesn't use far
            self._patch_near_jump(instr, displacement)

        elif opcode == 0x0F and len(old_bytes) >= 2:
            second = old_bytes[1]
            if 0x80 <= second <= 0x8F:
                # near conditional
                self._patch_near_conditional(instr, displacement)

        # else fallback to do nothing

        instr.relative_target = new_target
        return (instr.size != old_size)

    # ------------------------------------------------------------------
    # Helpers: short vs near jumps
    # ------------------------------------------------------------------
    def _in_short_range(self, disp):
        return -128 <= disp <= 127

    def _patch_short_jump(self, instr, displacement):
        """
        For short jmp or short cond, the second byte is rel8.
        For unconditional short jmp: opcode=0xEB
        For conditional short jmp: opcode=0x7X
        """
        import struct
        if len(instr.bytes) < 2:
            return
        disp_sbyte = self._pack_sbyte(displacement)
        new_bytes = bytearray(instr.bytes)
        new_bytes[1] = disp_sbyte
        instr.bytes = bytes(new_bytes)
        # short jmp is always 2 bytes
        instr.size = 2

    def _pack_sbyte(self, value):
        if value < -128 or value > 127:
            # if you are forcing it, or raise an error. Here we clamp:
            return 0
        return struct.pack("b", value)[0]

    def _upgrade_to_near_jmp(self, instr, displacement):
        """
        Convert short jmp (0xEB) -> near jmp (0xE9).
        Instruction goes from 2 bytes to 5 bytes.
        """
        import struct
        disp32 = struct.pack("<i", displacement)
        # 0xE9 disp32
        new_bytes = bytearray(5)
        new_bytes[0] = 0xE9
        new_bytes[1:5] = disp32

        instr.bytes = bytes(new_bytes)
        instr.size = 5

    def _upgrade_to_near_cond(self, instr, displacement):
        """
        Convert short conditional jump (0x7*) -> near conditional (0x0F 0x8*).
        If original was 0x74 (JE short), new => 0x0F 0x84 + rel32. => 6 bytes.
        """
        import struct
        opcode = instr.bytes[0]
        cond = opcode & 0x0F  # e.g. if 0x74 => cond=4
        second_byte = 0x80 | cond  # e.g. 0x84
        disp32 = struct.pack("<i", displacement)

        new_bytes = bytearray(6)
        new_bytes[0] = 0x0F
        new_bytes[1] = second_byte
        new_bytes[2:6] = disp32

        instr.bytes = bytes(new_bytes)
        instr.size = 6

    def _patch_near_jump(self, instr, displacement):
        """
        For near call/jmp (0xE8, 0xE9), store signed 32-bit after the opcode.
        """
        import struct
        if len(instr.bytes) < 5:
            # ensure we have at least 5 bytes
            new_bytes = bytearray(5)
            new_bytes[0] = instr.bytes[0]  # keep same opcode
            instr.bytes = bytes(new_bytes)
            instr.size = 5
        disp32 = struct.pack("<i", displacement)
        new_bytes = bytearray(instr.bytes)
        new_bytes[1:5] = disp32
        instr.bytes = bytes(new_bytes)
        instr.size = 5

    def _patch_near_conditional(self, instr, displacement):
        """
        For near conditional jumps => 0F 8?
        The displacement is 4 bytes starting at instr.bytes[2].
        E.g. 0F 84 + disp32 => 6 bytes total.
        """
        import struct
        if len(instr.bytes) < 6:
            # ensure 6 bytes
            base = bytearray(6)
            base[0:len(instr.bytes)] = instr.bytes
            instr.bytes = bytes(base)
            instr.size = 6
        disp32 = struct.pack("<i", displacement)
        new_bytes = bytearray(instr.bytes)
        new_bytes[2:6] = disp32
        instr.bytes = bytes(new_bytes)
        instr.size = 6

    # (Optional) If you do far jumps, handle them similarly...


#
# End of BlockObfuscator
#
