#!/usr/bin/python3

import argparse
from capstone import *


def parseArgs():
    # parse args
    parser = argparse.ArgumentParser("Disassemble shellcode from a file using the capstone engine")
    parser.add_argument("shellcode_file", help="The file which contains the shellcode to be disassembled")
    parser.add_argument("--offset", default=0, help="Specify the offset from which the to-be-disassembled shellcode starts")
    parser.add_argument("--length", default=-1, help="Specify how many bytes should be disassembled starting from the offset")
    parser.add_argument("--x86", action="store_true", help="Specify the target platform to be 32-bit (default is 64-bit")

    return parser.parse_args()


def main():
    # get parsed args
    args = parseArgs()

    # read the shellcode from the file
    with open(args.shellcode_file, "rb+") as f:
        code = f.read()
        if args.length < 0:
            code = code[args.offset:-1]
        else:
            code = code[args.offset:args.offset+args.length]
        
    # create capstone's disassembler object
    if args.x86:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_64)

    # disassemble the shellcode
    disassembly = md.disasm(code, 0x1000)
    for inst in disassembly:
        print(f"{hex(inst.address)}: \t{inst.mnemonic}\t{inst.op_str}")



if __name__ == "__main__":
    main()

