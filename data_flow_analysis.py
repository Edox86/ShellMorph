# data_flow_analysis.py

import logging
import capstone
from copy import deepcopy


class DataFlowAnalyzer:
    """
    An advanced data-flow analyzer for x86 instructions (32-bit or 64-bit).
    Performs:
      1. Backward liveness analysis.
      2. Forward pointer tracking to map registers to block references.

    Usage:
    1) Initialize with arch/mode if needed (CS_MODE_32 or CS_MODE_64).
    2) Call 'analyze(blocks)' passing your list of BasicBlock objects
       from 'block_builder.py'.
    3) The result includes:
       - Liveness information: block.live_in, block.live_out
       - Pointer information: block.out_reg_points
    """

    def __init__(self, arch=capstone.CS_ARCH_X86, mode=capstone.CS_MODE_64):
        self.arch = arch
        self.mode = mode
        self.logger = logging.getLogger(self.__class__.__name__)

    def analyze(self, blocks):
        """
        Main entry point:
         - Compute def/use for each instruction
         - Perform backward liveness analysis
         - Perform forward pointer tracking
        """
        self._compute_def_use(blocks)
        self._init_liveness(blocks)
        self._liveness_fixpoint(blocks)
        self._pointer_tracking(blocks)

    # ----------------------------------------------------
    # 1) Compute Def/Use for each instruction
    # ----------------------------------------------------
    def _compute_def_use(self, blocks):
        """
        For each instruction, parse Capstone to see which registers are read or written.
        Stores sets: instr.def_regs = set(), instr.use_regs = set().
        """
        for block in blocks:
            for instr in block.instructions:
                instr.def_regs = set()
                instr.use_regs = set()
                cs_ins = getattr(instr, 'capstone_ins', None)
                if not cs_ins:
                    # Fallback if we have no Capstone instruction object
                    continue

                # Determine registers read/written by calling Capstone's reg_access if available
                if hasattr(cs_ins, 'reg_access'):
                    # reg_access() => (regs_read, regs_write)
                    regs_read, regs_write = cs_ins.reg_access()
                    # Convert them to register names
                    for r in regs_read:
                        reg_name = cs_ins.reg_name(r)
                        instr.use_regs.add(reg_name.lower())
                    for r in regs_write:
                        reg_name = cs_ins.reg_name(r)
                        instr.def_regs.add(reg_name.lower())
                else:
                    # Fallback approach if 'reg_access()' is not available:
                    # Implement a naive def/use analysis based on operands
                    self._naive_def_use(instr)

    def _naive_def_use(self, instr):
        """
        Fallback if cs_ins.reg_access() is not available.
        Parses instr.capstone_ins.operands to guess usage.
        This is simplistic and won't catch partial registers or flags.
        """
        cs_ins = instr.capstone_ins
        if not cs_ins:
            return
        mnemonic = cs_ins.mnemonic.lower()
        operands = cs_ins.operands

        # Simplistic rules based on mnemonic and operand positions
        if mnemonic in ['mov', 'lea', 'add', 'sub', 'xor', 'or', 'and']:
            # Typically, first operand is destination (def), others are sources (use)
            if len(operands) >= 1:
                dest = operands[0]
                if dest.type == capstone.x86_const.X86_OP_REG:
                    reg_name = cs_ins.reg_name(dest.reg).lower()
                    instr.def_regs.add(reg_name)
            for op in operands[1:]:
                if op.type == capstone.x86_const.X86_OP_REG:
                    reg_name = cs_ins.reg_name(op.reg).lower()
                    instr.use_regs.add(reg_name)
        elif mnemonic in ['call', 'jmp']:
            # Calls and jumps typically use their target registers
            for op in operands:
                if op.type == capstone.x86_const.X86_OP_REG:
                    reg_name = cs_ins.reg_name(op.reg).lower()
                    instr.use_regs.add(reg_name)
        elif mnemonic in ['push', 'pop']:
            if len(operands) == 1:
                op = operands[0]
                if mnemonic == 'push':
                    if op.type == capstone.x86_const.X86_OP_REG:
                        reg_name = cs_ins.reg_name(op.reg).lower()
                        instr.use_regs.add(reg_name)
                elif mnemonic == 'pop':
                    if op.type == capstone.x86_const.X86_OP_REG:
                        reg_name = cs_ins.reg_name(op.reg).lower()
                        instr.def_regs.add(reg_name)
        # Add more mnemonics and rules as needed

    # ----------------------------------------------------
    # 2) Initialize liveness data structures
    # ----------------------------------------------------
    def _init_liveness(self, blocks):
        """
        Initializes live_in and live_out sets for each instruction in each block.
        """
        for block in blocks:
            n = len(block.instructions)
            block.live_in = [set() for _ in range(n)]
            block.live_out = [set() for _ in range(n)]
            # Initialize pointer tracking
            block.in_reg_points = {}
            block.out_reg_points = {}

    # ----------------------------------------------------
    # 3) Liveness Fixpoint (Backward Pass)
    # ----------------------------------------------------
    def _liveness_fixpoint(self, blocks):
        """
        Performs a standard backward liveness fixpoint:
         For each instruction i in block b,
           live_in[i] = use[i] U (live_out[i] - def[i])
           live_out[i] = union(live_in[i+1]) if i+1 in same block
                        plus union(live_in of first instr of successor blocks if i is last instr)
        Iterates until no changes occur.
        """
        changed = True
        while changed:
            changed = False
            for block in blocks:
                n = len(block.instructions)
                for i in reversed(range(n)):
                    instr = block.instructions[i]

                    old_in = block.live_in[i].copy()
                    old_out = block.live_out[i].copy()

                    # Compute new_out
                    new_out = set()
                    if i < n - 1:
                        # Next instruction in the same block
                        new_out = new_out.union(block.live_in[i + 1])
                    else:
                        # Last instruction in the block
                        for succ in getattr(block, 'successors', []):
                            if succ.instructions:
                                new_out = new_out.union(succ.live_in[0])

                    # Compute new_in
                    new_in = instr.use_regs.union(new_out - instr.def_regs)

                    # Check for changes
                    if new_in != old_in or new_out != old_out:
                        block.live_in[i] = new_in
                        block.live_out[i] = new_out
                        changed = True

    # ----------------------------------------------------
    # 4) Pointer Tracking (Forward Pass)
    # ----------------------------------------------------
    def _pointer_tracking(self, blocks):
        """
        Performs forward data-flow analysis to track which registers point to which blocks.
        Populates block.out_reg_points with mappings: {reg_name: BasicBlock}

        Handles a variety of instructions that can affect register mappings, including:
          - mov reg, imm
          - lea reg, [imm]
          - mov reg, reg
          - add reg, imm
          - sub reg, imm
          - xor reg, reg
          - inc reg
          - dec reg
          - push reg
          - pop reg
          - Other instructions that modify register values

        This comprehensive handling ensures accurate tracking of register references to blocks.
        """
        changed = True
        while changed:
            changed = False
            for block in blocks:
                # Merge out_reg_points from predecessors to form in_reg_points
                in_map = self._merge_predecessors(block, blocks)

                # If in_map differs from current block.in_reg_points, update and mark changed
                if in_map != block.in_reg_points:
                    block.in_reg_points = deepcopy(in_map)
                    changed = True

                # Compute out_reg_points by processing instructions
                new_out_map = deepcopy(block.in_reg_points)
                for instr in block.instructions:
                    cs_ins = instr.cs_ins
                    mnemonic = cs_ins.mnemonic.lower() if cs_ins else ""

                    # Handle 'mov reg, imm' and 'lea reg, [imm]'
                    if mnemonic in ['mov', 'lea']:
                        if len(instr.def_regs) >= 1:
                            dest_reg = next(iter(instr.def_regs))
                            # 'mov reg, imm'
                            if mnemonic == 'mov' and len(cs_ins.operands) >= 2:
                                src_op = cs_ins.operands[1]
                                if src_op.type == capstone.x86_const.X86_OP_IMM:
                                    imm_val = src_op.imm
                                    target_block = self._find_block_by_original_start(blocks, imm_val)
                                    if target_block:
                                        new_out_map[dest_reg] = target_block
                                        self.logger.debug(
                                            f"Register '{dest_reg}' is set to block starting at 0x{imm_val:X} via MOV."
                                        )
                                    else:
                                        # Immediate does not point to a known block; remove mapping
                                        if dest_reg in new_out_map:
                                            del new_out_map[dest_reg]
                                            self.logger.debug(
                                                f"Register '{dest_reg}' mapping removed via MOV (immediate does not point to a known block)."
                                            )
                            # 'lea reg, [mem]'
                            elif mnemonic == 'lea' and len(cs_ins.operands) >= 2:
                                src_op = cs_ins.operands[1]
                                if src_op.type == capstone.x86_const.X86_OP_MEM:
                                    # Calculate effective address if possible
                                    # For simplicity, handle 'lea reg, [base + disp]' without index scaling
                                    if src_op.mem.base == 0 and src_op.mem.index == 0:
                                        imm_val = src_op.mem.disp
                                        target_block = self._find_block_by_original_start(blocks, imm_val)
                                        if target_block:
                                            new_out_map[dest_reg] = target_block
                                            self.logger.debug(
                                                f"Register '{dest_reg}' is set to block starting at 0x{imm_val:X} via LEA."
                                            )
                                        else:
                                            # Displacement does not point to a known block; remove mapping
                                            if dest_reg in new_out_map:
                                                del new_out_map[dest_reg]
                                                self.logger.debug(
                                                    f"Register '{dest_reg}' mapping removed via LEA (displacement does not point to a known block)."
                                                )

                    # Handle 'mov reg, reg'
                    elif mnemonic == 'mov':
                        if len(instr.def_regs) >= 1 and len(instr.use_regs) >= 1:
                            dest_reg = next(iter(instr.def_regs))
                            src_reg = next(iter(instr.use_regs))
                            if src_reg in new_out_map:
                                new_out_map[dest_reg] = new_out_map[src_reg]
                                self.logger.debug(
                                    f"Register '{dest_reg}' is set to the same block as '{src_reg}' via MOV."
                                )
                            else:
                                if dest_reg in new_out_map:
                                    del new_out_map[dest_reg]
                                    self.logger.debug(
                                        f"Register '{dest_reg}' mapping removed via MOV (source register '{src_reg}' has no mapping)."
                                    )

                    # Handle 'add reg, imm' and 'sub reg, imm' - potentially modifies pointer
                    elif mnemonic in ['add', 'sub']:
                        if len(instr.def_regs) >= 1:
                            dest_reg = next(iter(instr.def_regs))
                            # If register is mapped, modifying it likely invalidates the pointer
                            if dest_reg in new_out_map:
                                del new_out_map[dest_reg]
                                self.logger.debug(
                                    f"Register '{dest_reg}' mapping removed via {mnemonic.upper()} (modifies register)."
                                )

                    # Handle 'xor reg, reg' - typically zeroes the register
                    elif mnemonic == 'xor':
                        if len(instr.def_regs) >= 1 and len(instr.use_regs) >= 1:
                            dest_reg = next(iter(instr.def_regs))
                            src_reg = next(iter(instr.use_regs))
                            if dest_reg == src_reg:
                                # 'xor reg, reg' zeroes the register; remove mapping
                                if dest_reg in new_out_map:
                                    del new_out_map[dest_reg]
                                    self.logger.debug(
                                        f"Register '{dest_reg}' mapping removed via XOR (register zeroed)."
                                    )

                    # Handle 'inc reg' and 'dec reg' - modifies register, invalidate mapping
                    elif mnemonic in ['inc', 'dec']:
                        if len(instr.def_regs) >= 1:
                            dest_reg = next(iter(instr.def_regs))
                            if dest_reg in new_out_map:
                                del new_out_map[dest_reg]
                                self.logger.debug(
                                    f"Register '{dest_reg}' mapping removed via {mnemonic.upper()} (modifies register)."
                                )

                    # Handle 'push reg' and 'pop reg'
                    elif mnemonic in ['push', 'pop']:
                        if len(instr.def_regs) >= 1:
                            dest_reg = next(iter(instr.def_regs))
                            # 'pop reg' assigns the popped value to the register; unclear mapping
                            # Conservative approach: remove any existing mapping
                            if dest_reg in new_out_map:
                                del new_out_map[dest_reg]
                                self.logger.debug(
                                    f"Register '{dest_reg}' mapping removed via {mnemonic.upper()} (stack operation)."
                                )
                        if len(instr.use_regs) >= 1:
                            src_reg = next(iter(instr.use_regs))
                            # 'push reg' reads the register; does not affect mapping
                            # No action needed
                            pass

                    # Handle other instructions that write to registers in a way that invalidates mappings
                    elif mnemonic in ['lea']:
                        # Already handled above
                        pass
                    else:
                        # For other instructions that define registers, remove mappings unless explicitly handled
                        if len(instr.def_regs) >= 1:
                            for dest_reg in instr.def_regs:
                                if dest_reg in new_out_map:
                                    del new_out_map[dest_reg]
                                    self.logger.debug(
                                        f"Register '{dest_reg}' mapping removed via {mnemonic.upper()} (generic register write)."
                                    )

                    # Additional instruction types can be handled here as needed

                # After processing all instructions, check if out_reg_points changed
                if new_out_map != block.out_reg_points:
                    block.out_reg_points = new_out_map
                    changed = True

        self.logger.info("Completed pointer tracking.")

    def _merge_predecessors(self, block, blocks):
        """
        Merges the out_reg_points from all predecessor blocks to form in_reg_points for the current block.
        If a register is mapped to different blocks across predecessors, it is removed from the mapping.

        :param block: The current BasicBlock being processed.
        :param blocks: List of all BasicBlock objects.
        :return: Merged register to block mapping.
        """
        merged_map = {}
        predecessors = self._find_predecessors(block, blocks)
        if not predecessors:
            return merged_map  # No predecessors, empty map

        # Initialize merged_map with the first predecessor's out_reg_points
        merged_map = deepcopy(predecessors[0].out_reg_points)

        # Iterate over remaining predecessors and intersect mappings
        for pred in predecessors[1:]:
            keys_to_remove = []
            for reg, blk in merged_map.items():
                if reg not in pred.out_reg_points or pred.out_reg_points[reg] != blk:
                    keys_to_remove.append(reg)
            for reg in keys_to_remove:
                del merged_map[reg]

        return merged_map

    def _find_predecessors(self, block, blocks):
        """
        Finds all predecessor blocks of the given block.

        :param block: The BasicBlock for which to find predecessors.
        :param blocks: List of all BasicBlock objects.
        :return: List of predecessor BasicBlock objects.
        """
        predecessors = []
        for potential_pred in blocks:
            if hasattr(potential_pred, 'successors') and block in potential_pred.successors:
                predecessors.append(potential_pred)
        return predecessors

    def _find_block_by_original_start(self, blocks, addr):
        """
        Finds a block whose original_start matches the given address.

        :param blocks: List of all BasicBlock objects.
        :param addr: The address to match.
        :return: The matching BasicBlock object or None.
        """
        for block in blocks:
            if hasattr(block, 'original_start') and block.original_start == addr:
                return block
        return None

