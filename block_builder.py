# block_builder.py

import logging

class BasicBlock:
    """
    Represents a linear sequence of instructions, typically ending with
    a jump/ret or branching instruction. Each block has a unique ID for reference.
    """

    def __init__(self, block_id):
        self.block_id = block_id
        self.instructions = []
        self.start_address = None
        # Potentially track end_address, though we can compute it on the fly.
        self.successors = []  # List of other BasicBlocks we can jump/fall through to.

    @property
    def end_address(self):
        if not self.instructions:
            return None
        last = self.instructions[-1]
        return last.address + last.size - 1

    def add_instruction(self, instr):
        if not self.instructions:
            self.start_address = instr.address
        self.instructions.append(instr)

    def __str__(self):
        start = f"0x{self.start_address:016X}" if self.start_address else "None"
        end = f"0x{self.end_address:016X}" if self.end_address else "None"
        return f"Block#{self.block_id} [{start}-{end}] ({len(self.instructions)} instrs)"

    def debug_print(self):
        """
        Print details of the block and the instructions within.
        """
        print(str(self))
        for ins in self.instructions:
            print("   " + ins.debug_info())


class BlockBuilder:
    """
    Groups analyzed instructions (from instruction_analysis) into BasicBlocks.
    - By default, ends a block if we see an unconditional jump, ret,
      or if the next instruction is a known jump target.
    - Optionally treat 'call' instructions as block terminators, if desired.

    Also computes 'successors' for each block:
    - If last instruction is unconditional jump => 1 successor (the jump target) if found
    - If last instruction is conditional jump => 2 successors (taken + fall-through) if both exist
    - If last instruction is ret => no successor
    - Otherwise => 1 successor (fall-through), if the next block starts right after
    """

    def __init__(self, treat_calls_as_end=False):
        """
        :param treat_calls_as_end: If True, treat a 'call' instruction as a block terminator as well.
        """
        self.treat_calls_as_end = treat_calls_as_end
        self.logger = logging.getLogger(__name__)

    def build_blocks(self, instructions):
        """
        instructions: a list of AnalyzedInstruction, sorted by address ascending.
        Returns: list of BasicBlock
        """
        if not instructions:
            return []

        # 1) Sort instructions by address
        instructions.sort(key=lambda i: i.address)

        # 2) Collect all addresses that are jump targets, so we know potential block boundaries
        jump_targets = set()
        for ins in instructions:
            if ins.relative_target is not None:
                jump_targets.add(ins.relative_target)

        # Map from address -> instruction for quick lookups
        instr_map = {ins.address: ins for ins in instructions}

        # We'll create blocks by scanning linearly.
        blocks = []
        current_block = None
        block_id_counter = 0

        for idx, ins in enumerate(instructions):
            # If we should start a new block
            # Conditions:
            #  - current_block is None (no block started yet),
            #  - OR this instruction address is in jump_targets (someone jumps here),
            #  - OR the previous instruction ended the block.
            start_new_block = False

            if current_block is None:
                start_new_block = True
            else:
                # Check if the previous instruction was unconditional jump or ret
                prev_ins = current_block.instructions[-1]
                if (prev_ins.is_jump and not prev_ins.is_conditional) or prev_ins.is_ret:
                    # definitely start new block
                    start_new_block = True
                elif self.treat_calls_as_end and prev_ins.is_call:
                    # optionally treat calls as block terminators
                    start_new_block = True
                else:
                    # If this instruction is a known jump target, that also triggers new block
                    if ins.address in jump_targets:
                        start_new_block = True

            if start_new_block:
                # If we have a current block in progress, add it to blocks
                if current_block and current_block.instructions:
                    blocks.append(current_block)
                # Create a new block
                current_block = BasicBlock(block_id_counter)
                block_id_counter += 1

            # Add the instruction to the current block
            current_block.add_instruction(ins)

        # If there's a leftover block
        if current_block and current_block.instructions:
            blocks.append(current_block)

        # 3) Compute successors
        self._compute_successors(blocks, instr_map)

        return blocks

    def _compute_successors(self, blocks, instr_map):
        """
        For each block, figure out its successors.
        We'll do a naive approach:
          - If last instr is unconditional jump => 1 successor (the jump target), if valid
          - If last instr is conditional => 2 successors (taken + fall-through), if valid
          - If last instr is ret => 0 successors
          - Otherwise => 1 successor (fall-through), if the next instr is recognized
        """
        # Build a map from start_address -> block
        block_map = {b.start_address: b for b in blocks}

        for block in blocks:
            if not block.instructions:
                continue
            last_ins = block.instructions[-1]

            if last_ins.is_ret:
                # no successors
                continue

            if last_ins.is_jump:
                # if relative_target is valid, that's one successor
                if last_ins.relative_target is not None:
                    succ_block = self._find_block_for_address(block_map, last_ins.relative_target)
                    if succ_block:
                        block.successors.append(succ_block)
                    else:
                        self.logger.debug(f"No block found for jump target 0x{last_ins.relative_target:X}")

                # if conditional => also consider fall-through
                if last_ins.is_conditional:
                    fall_through_addr = last_ins.address + last_ins.size
                    succ_block_ft = self._find_block_for_address(block_map, fall_through_addr)
                    if succ_block_ft:
                        block.successors.append(succ_block_ft)
            elif last_ins.is_call:
                # If we treat calls as block terminators, we might want a "return address" block,
                # i.e. fall-through. Or do advanced subroutine analysis.
                # In a naive approach, we just consider the fall-through:
                fall_through_addr = last_ins.address + last_ins.size
                succ_block_ft = self._find_block_for_address(block_map, fall_through_addr)
                if succ_block_ft:
                    block.successors.append(succ_block_ft)
            else:
                # normal fall-through
                fall_through_addr = last_ins.address + last_ins.size
                succ_block_ft = self._find_block_for_address(block_map, fall_through_addr)
                if succ_block_ft:
                    block.successors.append(succ_block_ft)

    def _find_block_for_address(self, block_map, addr):
        """
        Return the block that starts at 'addr', if any.
        If instructions are strictly sequential, a block starts exactly at an instruction address.
        Otherwise, we might need a more complex approach (like searching blocks by range).
        """
        return block_map.get(addr, None)
