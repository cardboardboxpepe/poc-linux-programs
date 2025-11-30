import sys
import argparse
from pathlib import Path
from base64 import b64encode

from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def get_function_bytes(path: Path, func: str) -> bytes:
    with open(path, "rb") as f:
        elf = ELFFile(f)

        # Find the symbol table (.symtab)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise RuntimeError("No .symtab found (binary may be stripped)")

        # Find the function symbol
        sym = None
        for s in symtab.iter_symbols():
            if s.name == func and s["st_size"] > 0:
                sym = s
                break

        if sym is None:
            raise RuntimeError(f"Function '{func}' not found or st_size == 0")

        # function data
        func_addr = sym["st_value"]  # virtual address
        func_size = sym["st_size"]  # nb bytes

        # Find which section contains the function
        sec = elf.get_section(sym["st_shndx"])
        sec_addr = sec["sh_addr"]
        sec_offset = sec["sh_offset"]

        # Calculate file offset of function
        file_off = sec_offset + (func_addr - sec_addr)

        # Read its bytes
        f.seek(file_off)
        return f.read(func_size)


def overwrite_function(path: Path, syms: list[str]):
    with open(path, "rb+") as f:
        elf = ELFFile(f)

        # Find the symbol table (.symtab)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise RuntimeError("No .symtab found (binary may be stripped)")

        for func in syms:
            # Find the function symbol
            sym = None
            for s in symtab.iter_symbols():
                if s.name == func and s["st_size"] > 0:
                    sym = s
                    break

            if sym is None:
                raise RuntimeError(f"Function '{func}' not found or st_size == 0")

            # function data
            func_addr = sym["st_value"]  # virtual address
            func_size = sym["st_size"]  # nb bytes

            # Find which section contains the function
            sec = elf.get_section(sym["st_shndx"])
            sec_addr = sec["sh_addr"]
            sec_offset = sec["sh_offset"]

            # Calculate file offset of function
            file_off = sec_offset + (func_addr - sec_addr)

            # Read its bytes
            f.seek(file_off)
            if f.write(b"\x90" * func_size) != func_size:
                raise RuntimeError(f"error overwriting function {sym}")

            # log
            print(f"overwrite {func_size} bytes of function {func} with NOPs")


def disasm(code_bytes, start_addr=0x0):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False  # no extra info, just mnemonics

    for insn in md.disasm(code_bytes, start_addr):
        print(f"0x{insn.address:016x}:  {insn.mnemonic} {insn.op_str}")


def create_embed_file(
    blob: Path, align: int, symbol: str, file: Path, output: Path
) -> int:
    # check align
    if align <= 0:
        print(f"align must be greater than zero, was {align}")
        return 1

    # check symbol
    if len(symbol) == 0:
        print(f"symbol must be a valid string, was {symbol}")
        return 1

    # check files
    if not file.exists():
        print(f"the main binary at {file} doesn't exist!")
        return 1
    if not blob.exists():
        print(f"the blob at {blob} doesn't exist!")
        return 1

    # -- main logic --
    try:
        # get the size of the function
        contents = get_function_bytes(file, symbol)

        # print the bytes of sym
        print(f"disassembly of {symbol}")
        disasm(contents)

        # log
        print(f"function {symbol} is {len(contents)} bytes long")

        # open the blob
        bb = blob.read_bytes()
        print(f"read {len(bb)} bytes from {blob}")

        # form the payload
        payload = b64encode(contents) + b"\0"
        print(f"encoded payload is now {len(payload)} from {len(contents)}")

        # overwrite
        payload += bb[len(payload) : align]

        # write to file
        nb_written = output.write_bytes(payload)
        print(f"wrote {nb_written} bytes to {output}")
    except Exception as e:
        print(f"encountered exception: {e}")
        return 1

    # OK
    return 0


def create_prep_file(size: int, output: Path) -> int:
    # check the size
    if size <= 0:
        print(f"size must be greater than zero, was {size}")
        return 1

    # forming the payload
    payload = b"\x90" * (size - 1)
    payload = b64encode(payload) + b"\0"

    # trimming
    payload = payload[:size]

    # write to file
    nb_written = output.write_bytes(payload)
    print(f"wrote {nb_written} (aligned to {size}) bytes to {output}")

    # OK
    return 0


def overwrite_file(output: Path, file: Path, symbols: list[str]):
    # make a copy of the file
    nbwritten = output.write_bytes(file.read_bytes())
    print(f"wrote {nbwritten} bytes to {output}")

    # overwrite functions
    overwrite_function(output, symbols)

    # logging
    print(f"overwrote {len(symbols)} syms")


parser = argparse.ArgumentParser(
    description="The helper script for the self-modifying program"
)

# a toggle group
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument(
    "--prep",
    dest="prep",
    action="store_true",
    help="Create a blob of bytes as a template",
    default=False,
)
group.add_argument(
    "--embed",
    dest="embed",
    action="store_true",
    help="Encode the function's data in base64 for embedding",
    default=False,
)
group.add_argument(
    "--overwrite",
    dest="overwrite",
    action="store_true",
    help="Overwrite the function with nop instructions",
    default=False,
)

## options for --overwrite
overwrite_options = parser.add_argument_group(
    "overwrite options", description="Arguments for the --overwrite flag"
)
overwrite_options.add_argument(
    "--symbols",
    dest="symbols",
    type=str,
    nargs="+",
    help="The symbols to overwrite with nops",
)

## options for --prep
prep_options = parser.add_argument_group(
    "prep options", description="Arguments for the --prep flag"
)

## options for --embed
embed_options = parser.add_argument_group(
    "embed options", description="Arguments for the --embed flag"
)
embed_options.add_argument(
    "-S",
    "--symbol",
    dest="symbol",
    type=str,
    help="The symbol to lookup in the binary",
)
embed_options.add_argument(
    "-b",
    "--blob",
    dest="blob",
    type=str,
    help="The blob file that was used to link the given symbol",
)

## general arguments

# the path to the file that's outputted by this program
parser.add_argument(
    "-f",
    "--file",
    dest="file",
    type=str,
    help="An ELF file, only meaningful for --embed and --overwrite",
)
parser.add_argument(
    "-o",
    "--output",
    dest="output",
    type=str,
    help="The path to the output file",
)
parser.add_argument(
    "-a",
    "--align",
    dest="align",
    type=int,
    help="Used to align the blob/base64 encoded function to a given value",
)

if __name__ == "__main__":
    # parse args
    args = parser.parse_args()

    # check the output path
    if not args.output and not args.overwrite:
        print("no output path specified")
        sys.exit(1)
    output = Path(args.output)

    # switch
    if args.embed:
        # cast args
        file = Path(args.file)
        blob = Path(args.blob)

        # call main function
        sys.exit(
            create_embed_file(
                blob=blob,
                align=args.align,
                symbol=args.symbol,
                file=file,
                output=output,
            )
        )
    elif args.prep:
        sys.exit(create_prep_file(size=args.align, output=output))
    elif args.overwrite:
        # cast args
        file = Path(args.file)

        sys.exit(overwrite_file(output=output, file=file, symbols=args.symbols))
    else:
        print("invalid mode")
        sys.exit(1)
