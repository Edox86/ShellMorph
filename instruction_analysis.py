# instruction_analysis.py

import capstone
import struct
import re

class AnalyzedInstruction:
    """
    Holds detailed information about a single machine-code instruction,
    including advanced metadata for obfuscation tasks.
    """

    def __init__(self, address, size, mnemonic, op_str, raw_bytes, capstone_ins=None):
        """
        :param address: The runtime/disassembly address of the instruction
        :param size: Size of the instruction in bytes
        :param mnemonic: Instruction mnemonic (e.g., 'jmp', 'mov')
        :param op_str: Operand string (e.g., 'rax, rbx')
        :param raw_bytes: The raw bytes of the instruction
        :param capstone_ins: (Optional) The original Capstone Instruction object
        """
        self.address = address
        self.size = size
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.bytes = raw_bytes
        self.cs_ins = capstone_ins  # Original Capstone instruction

        # Basic flags
        self.is_jump = False
        self.is_call = False
        self.is_ret = False
        self.is_conditional = False
        self.is_relative = False
        self.is_short_jump = False
        self.is_data_reference = False
        self.uses_sse_avx = False

        # Extended fields
        self.relative_target = None  # If relative jump/call
        self.segment_override = None  # e.g., "FS", "GS"
        self.rex_prefix = None       # e.g., "REX.W", etc.
        self.is_invalid = False      # Mark if an error occurs

        # Metadata for indirect references
        self.is_indirect_code_ref = False
        self.mem_base_reg = None
        self.mem_index_reg = None
        self.mem_scale = 1
        self.mem_disp = 0

    def __str__(self):
        return f"0x{self.address:016X}: {self.mnemonic:<8} {self.op_str}"

    def debug_info(self):
        """
        Return a string summarizing advanced metadata, for debug.
        """
        flags = []
        if self.is_jump: flags.append("JMP")
        if self.is_call: flags.append("CALL")
        if self.is_ret:  flags.append("RET")
        if self.is_conditional: flags.append("COND")
        if self.is_relative: flags.append("REL")
        if self.is_short_jump: flags.append("SHORT")
        if self.is_data_reference: flags.append("DATA")
        if self.uses_sse_avx: flags.append("SSE/AVX")
        if self.is_invalid: flags.append("INVALID")

        flag_str = "|".join(flags) if flags else "NONE"
        # Segment override / REX
        seg = f", SEG={self.segment_override}" if self.segment_override else ""
        rex = f", REX={self.rex_prefix}" if self.rex_prefix else ""

        tgt = f" => 0x{self.relative_target:016X}" if self.relative_target else ""
        return f"{str(self)} [{flag_str}{seg}{rex}]{tgt}"


class InstructionAnalyzer:
    """
    Processes raw disassembly output (from our Disassembler) into AnalyzedInstruction objects,
    with advanced metadata like:
      - Distinguish short vs near jumps
      - Comprehensive conditional jump detection
      - Segment override prefixes
      - REX prefix usage
      - Exception handling for malformed instructions
    """

    def __init__(self, arch=capstone.CS_ARCH_X86, mode=capstone.CS_MODE_64):
        self.arch = arch
        self.mode = mode

    def analyze_instructions(self, disasm_list):
        """
        :param disasm_list: A list of dicts from Disassembler.disassemble_shellcode.
                            Each dict includes:
                              'address', 'size', 'mnemonic', 'op_str', 'bytes', 'instruction'
        :return: List[AnalyzedInstruction] with advanced metadata.
        """
        analyzed = []

        for ins_dict in disasm_list:
            # We wrap each instruction analysis in a try/except
            # so a single malformed instruction won't crash the entire pipeline.
            try:
                inst = AnalyzedInstruction(
                    address=ins_dict['address'],
                    size=ins_dict['size'],
                    mnemonic=ins_dict['mnemonic'],
                    op_str=ins_dict['op_str'],
                    raw_bytes=ins_dict['bytes'],
                    capstone_ins=ins_dict['instruction']
                )

                self._analyze_flags(inst)
                self._detect_data_references(inst)
                self._analyze_prefixes(inst)

                if inst.is_relative:
                    inst.relative_target = self._compute_relative_target(inst)

                # SSE/AVX usage
                self._check_sse_avx_usage(inst)

                self._detect_indirect_mem_call_jump(inst)

            except Exception as e:
                # Mark instruction as invalid if something goes wrong
                inst = AnalyzedInstruction(
                    address=ins_dict.get('address', 0),
                    size=ins_dict.get('size', 0),
                    mnemonic="??",
                    op_str="",
                    raw_bytes=ins_dict.get('bytes', b""),
                    capstone_ins=None
                )
                inst.is_invalid = True

            analyzed.append(inst)

        return analyzed

    def _detect_indirect_mem_call_jump(self, instr):
        """
        Detect if the instruction is a call/jump with an indirect memory operand
        (e.g., call [ebp + 0x04], jmp [eax + ebx*2 + 0x08], etc.).
        If so, store relevant information to facilitate later updates.
        """
        # Initialize default values
        instr.is_indirect_code_ref = False
        instr.mem_base_reg = None
        instr.mem_index_reg = None
        instr.mem_scale = 1
        instr.mem_disp = 0

        # Check if the instruction is a call or jump
        if not (instr.is_call or instr.is_jump):
            return  # Not a call or jump, no need to proceed

        # Ensure Capstone's detailed mode is enabled
        cs_ins = instr.cs_ins
        if not cs_ins or not cs_ins.operands:
            return  # No operands to analyze

        # Iterate over operands to find memory operands
        for op in cs_ins.operands:
            if op.type == capstone.x86_const.X86_OP_MEM:
                # Found a memory operand; proceed to extract details
                instr.is_indirect_code_ref = True

                # Extract base register, index register, scale, and displacement
                base_reg = op.mem.base
                index_reg = op.mem.index
                scale = op.mem.scale
                disp = op.mem.disp

                # Convert register IDs to names, if they exist
                if base_reg != 0:
                    instr.mem_base_reg = cs_ins.reg_name(base_reg).lower()
                if index_reg != 0:
                    instr.mem_index_reg = cs_ins.reg_name(index_reg).lower()
                instr.mem_scale = scale
                instr.mem_disp = disp

                # Since x86/x64 typically have at most one memory operand per instruction,
                # we can break after processing the first one
                break

    def _analyze_flags(self, inst: AnalyzedInstruction):
        """
        Determine jump/call/ret, short vs near jump, conditional, etc.
        This is more comprehensive for x86: includes 0x7* short cond jumps, 0x0F 0x8* near cond jumps,
        loop instructions, etc.
        """
        cs_ins = inst.cs_ins
        if not cs_ins:
            return

        # Basic group checks
        if capstone.CS_GRP_JUMP in cs_ins.groups:
            inst.is_jump = True
        if capstone.CS_GRP_CALL in cs_ins.groups:
            inst.is_call = True
        if capstone.CS_GRP_RET in cs_ins.groups:
            inst.is_ret = True

        # Distinguish conditional vs. unconditional jump
        # For x86, Capstone sets CS_GRP_JUMP for both, so we look at mnemonic or check conditions
        if inst.is_jump:
            lower_mnem = inst.mnemonic.lower()
            # Exclude 'jmp', 'ljmp', 'jmpf' (far jump), etc.
            if lower_mnem.startswith('j') and lower_mnem not in ['jmp', 'ljmp', 'jmpf']:
                # 'je', 'jne', 'ja', 'jb', 'jg', 'loop'?
                inst.is_conditional = True

        # Distinguish short vs near jump
        #  - short unconditional jmp = 0xEB
        #  - short cond = 0x7* (like 0x74=je, 0x75=jne)
        #  - near jmp = 0xE9, near call = 0xE8, near cond = 0x0F 0x8*
        first_byte = inst.bytes[0] if inst.bytes else 0
        if inst.is_jump or inst.is_call:
            if first_byte == 0xEB:
                inst.is_short_jump = True
            elif 0x70 <= first_byte <= 0x7F:
                # short conditional jump
                inst.is_short_jump = True
            elif self._is_loop_instruction(inst):
                # "loop", "loope", "loopne", "loopz", "loopnz" => also short jumps in x86
                inst.is_short_jump = True

        # If it’s a jump/call, check if it’s relative by checking for immediate operand (common for x86).
        if (inst.is_jump or inst.is_call) and self._has_relative_operand(cs_ins):
            inst.is_relative = True

    def _is_loop_instruction(self, inst: AnalyzedInstruction):
        """
        Check if the mnemonic is one of the loop-based instructions in x86 (which are short jumps).
        """
        loops = ['loop', 'loope', 'loopne', 'loopnz', 'loopz', 'loopn', 'jcxz', 'jecxz']
        return inst.mnemonic.lower() in loops

    def _has_relative_operand(self, cs_ins):
        """
        For x86_64, check if there's an immediate operand typically used as rel offset.
        """
        if not cs_ins.operands:
            return False
        import capstone.x86_const as x86const
        for op in cs_ins.operands:
            if op.type == x86const.X86_OP_IMM:
                return True
        return False

    def _compute_relative_target(self, inst: AnalyzedInstruction):
        """
        If short or near jump/call, compute final target.
        More comprehensive coverage for short/near unconditional, conditional, loop, etc.
        """
        cs_ins = inst.cs_ins
        if not cs_ins:
            return None

        import capstone.x86_const as x86const
        # We'll do a more thorough check of the bytes:
        first_byte = inst.bytes[0] if inst.bytes else 0

        # For each operand:
        for op in cs_ins.operands:
            if op.type == x86const.X86_OP_IMM:
                # This might be final absolute or just displacement, depending on Capstone build
                possible_imm = op.imm
                # Try specific checks for short vs near

                # Short unconditional jump => 0xEB (rel8)
                if first_byte == 0xEB and inst.size >= 2:
                    disp_sbyte = struct.unpack("b", inst.bytes[1:2])[0]
                    return inst.address + inst.size + disp_sbyte

                # Short conditional => 0x7* or loop => also rel8
                if 0x70 <= first_byte <= 0x7F and inst.size >= 2:
                    disp_sbyte = struct.unpack("b", inst.bytes[1:2])[0]
                    return inst.address + inst.size + disp_sbyte
                if self._is_loop_instruction(inst) and inst.size >= 2:
                    # loop instructions store an 8-bit displacement
                    disp_sbyte = struct.unpack("b", inst.bytes[1:2])[0]
                    return inst.address + inst.size + disp_sbyte

                # near call => 0xE8 rel32, near jmp => 0xE9 rel32
                if first_byte in (0xE8, 0xE9) and inst.size >= 5:
                    disp = struct.unpack("<i", inst.bytes[1:5])[0]
                    return inst.address + inst.size + disp

                # near conditional => 0x0F 0x8* => rel32
                if first_byte == 0x0F and inst.size >= 6:
                    second_opcode = inst.bytes[1]
                    if 0x80 <= second_opcode <= 0x8F:
                        disp = struct.unpack("<i", inst.bytes[2:6])[0]
                        return inst.address + inst.size + disp

                # fallback
                return possible_imm
        return None

    def _detect_data_references(self, inst: AnalyzedInstruction):
        """
        Some instructions (like 'mov rax, 0x404050') might have an immediate that references data.
        We do a naive check for large addresses, ignoring code range.
        """
        cs_ins = inst.cs_ins
        if not cs_ins or inst.is_jump or inst.is_call:
            return
        import capstone.x86_const as x86const
        for op in cs_ins.operands:
            if op.type == x86const.X86_OP_IMM:
                imm_val = op.imm
                # Heuristic: if imm is above some threshold, guess it's a data pointer
                if imm_val > 0x100000:  # arbitrary
                    inst.is_data_reference = True

    def _check_sse_avx_usage(self, inst: AnalyzedInstruction):
        """
        If the instruction uses SSE/AVX registers or is known SSE/AVX opcode.
        We'll do a mnemonic or operand check for 'xmm', 'ymm', 'zmm'.
        """
        if not inst.cs_ins:
            return
        lower_mnem = inst.mnemonic.lower()
        if any(reg in inst.op_str.lower() for reg in ["xmm", "ymm", "zmm"]):
            inst.uses_sse_avx = True

    def _analyze_prefixes(self, inst: AnalyzedInstruction):
        """
        Check segment overrides (FS, GS, CS, DS, SS, ES) and REX prefix usage in x86_64.

        - Some Capstone builds store prefix data in cs_ins.prefix.
        - Others store segment override in cs_ins.x86.segment or cs_ins.x86.prefix.
        - REX prefix might appear in cs_ins.x86.rex if compiled with X86_FEATURE_REX.
        """
        cs_ins = inst.cs_ins
        if not cs_ins or self.arch != capstone.CS_ARCH_X86:
            return

        try:
            # Segment override
            # In many Capstone versions, segment override is in cs_ins.x86.prefix[0] if it’s recognized
            # or cs_ins.x86.seg_override. We'll do a fallback approach.
            seg_reg = cs_ins.x86.seg_override  # might be e.g. capstone.x86_const.X86_REG_FS
            if seg_reg != 0:
                # Convert that to a string name, e.g. "FS", "GS"
                seg_name = cs_ins.reg_name(seg_reg)
                inst.segment_override = seg_name.upper() if seg_name else None

            # REX prefix
            # cs_ins.x86.rex might be 0 if no REX prefix, or a bitmask if present
            rex_val = cs_ins.x86.rex
            if rex_val != 0:
                # We'll do a naive decode. For example, REX.W = 0x8, REX.R = 0x4, etc.
                rex_strs = []
                if rex_val & 0x8:
                    rex_strs.append("REX.W")
                if rex_val & 0x4:
                    rex_strs.append("REX.R")
                if rex_val & 0x2:
                    rex_strs.append("REX.X")
                if rex_val & 0x1:
                    rex_strs.append("REX.B")

                inst.rex_prefix = "|".join(rex_strs) if rex_strs else "REX"

        except AttributeError:
            # Some older or differently compiled Capstone versions might not have x86.rex or x86.seg_override
            pass
        except Exception:
            # Catch-all in case something else goes wrong
            pass
