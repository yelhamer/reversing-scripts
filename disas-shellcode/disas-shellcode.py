#!/usr/bin/python3

import argparse
from capstone import *


# Argument Parser
def parseArgs():
    # parse args
    parser = argparse.ArgumentParser("disas-shellcode.py", description="Disassemble a portion of a file, with the option to xor it with a specified value before disassembly")
    parser.add_argument('shellcode_file', help="The file which contains the shellcode to be disassembled")
    parser.add_argument('-o', '--offset', default=0, help="Specify the offset from which the to-be-disassembled shellcode starts")
    parser.add_argument('-l', '--length', default=-1, help="Specify how many bytes should be disassembled starting from the offset")
    parser.add_argument('-x', '--xor', default=False, help="xor the shellcode with a value (Example: 0xdeadf). The value must be in hex and preceeded by 0x")
    parser.add_argument("--x86", action="store_true", help="Specify the target platform to be 32-bit (default is 64-bit")

    return parser.parse_args()


# Main function
def main():
    # get parsed args
    args = parseArgs()
    length = int(args.length)
    offset = int(args.offset, 16)

    # read the shellcode from the file
    with open(args.shellcode_file, "rb+") as f:
        code = list(f.read())
        if length < 0:
            code = code[offset:-1]
        else:
            code = code[offset:offset+length]
        
    # xor the shellcode if requested
    if args.xor:
        # format the xor argument
        if len(args.xor) % 2 == 0:
            xor_value = args.xor[2:]
        else:
            xor_value = "0"+args.xor[2:]

        # slice the provided hex value into bytes
        xor_value = [xor_value[i:i+2] for i in range(0, len(xor_value), 2)]
        xor_value = list(map(lambda x: int(x, 16), xor_value))
        xor_value = list(reversed(xor_value))

        # set modulo according to which the shellcode will be xored
        step = len(xor_value)
        
        # xor the shellcode one chunk at a time
        for i in range(0, len(code), step):
            code[i:i+step] = [j ^ k for j, k in zip(code[i:i+step], xor_value)]


    # create capstone's disassembler object
    if args.x86:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_64)

    # disassemble the shellcode
    print("[Disassembly]:")
    disassembly = md.disasm(bytes(code), 0x1000)
    for inst in disassembly:
        print(f"{hex(inst.address)}: \t{inst.mnemonic}\t{inst.op_str}")


# Entry point
if __name__ == "__main__":
    main()

