import sys
import argparse
from pathlib import Path

from elftools.elf.elffile import ELFFile


def get_function_size(path, func_name) -> tuple[int]:
    with open(path, "rb") as f:
        elf = ELFFile(f)

        # Find .symtab (static symbol table)
        symtab = None
        for section in elf.iter_sections():
            if section["sh_type"] == "SHT_SYMTAB":
                symtab = section
                break

        if symtab is None:
            raise RuntimeError("No .symtab found (binary may be stripped).")

        # Collect all function symbols
        func_syms = []
        target_sym = None
        for sym in symtab.iter_symbols():
            st_info_type = sym["st_info"]["type"]
            if st_info_type != "STT_FUNC":
                continue

            name = sym.name
            value = sym["st_value"]
            size = sym["st_size"]

            func_syms.append(sym)
            if name == func_name:
                target_sym = sym

        if target_sym is None:
            raise RuntimeError(f"Function '{func_name}' not found in .symtab")

        # If st_size is set, use it directly
        if target_sym["st_size"] > 0:
            return target_sym["st_size"]

        # Otherwise, approximate from the next function by address
        target_addr = target_sym["st_value"]
        higher_funcs = [s for s in func_syms if s["st_value"] > target_addr]

        if not higher_funcs:
            raise RuntimeError(f"No following function to infer size for '{func_name}'")

        next_sym = min(higher_funcs, key=lambda s: s["st_value"])
        return next_sym["st_value"] - target_addr


def create_embed_file(align: int, symbol: str, file: Path, output: Path) -> int:
    # check align
    if align <= 0:
        print(f"align must be greater than zero, was {align}")
        return 1

    # check symbol
    if len(symbol) == 0:
        print(f"symbol must be a valid string, was {symbol}")
        return 1

    # check file
    if not file.exists():
        print(f"the file at {file} doesn't exist!")
        return 1

    # -- main logic --
    try:
        # get the size of the function
        size = get_function_size(file, symbol)

        # log
        print(f"function {symbol} is {size} bytes long")
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

    # write to file
    output.write_bytes(b"A" * size)

    # OK
    return 0


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
    dest="overwite",
    action="store_true",
    help="Overwrite the function with nop instructions",
    default=False,
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
    "-f",
    "--file",
    dest="file",
    type=str,
    help="The target binary to search the symbol in",
)

## general arguments

# the path to the file that's outputted by this program
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
    if len(args.output) == 0:
        print(f"invalid output path, was {args.output}")
        sys.exit(1)
    output = Path(args.output)

    # switch
    if args.embed:
        # cast args
        file = Path(args.file)

        sys.exit(
            create_embed_file(
                align=args.align, symbol=args.symbol, file=file, output=output
            )
        )
    elif args.prep:
        sys.exit(create_prep_file(size=args.align, output=output))
    elif args.overwrite:
        print("overwrite not implemented yet!")
        sys.exit(0)
    else:
        print("invalid mode")
        sys.exit(1)
