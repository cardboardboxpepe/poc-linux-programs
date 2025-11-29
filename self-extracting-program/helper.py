import sys
import base64
import argparse
from pathlib import Path

KEY = [0xDE, 0xAD, 0xBE, 0xEF]


def xorcipher(inbytes: bytes) -> bytes:
    """
    Simple XOR cipher.
    """
    ret = []

    for index, b in enumerate(inbytes):
        ret.append(b ^ KEY[index % len(KEY)])

    return bytes(ret)


def main(
    in_file: str,
    out_file: str,
    read_base64: bool,
    write_base64: bool,
) -> int:
    inpath = Path(in_file).absolute().resolve()
    outpath = Path(out_file).absolute().resolve()

    # check if the in_file exists
    if not inpath.exists():
        sys.stderr.write(f"The input file {inpath} doesn't exist, aborting.\n")
        return 1

    # read in bytes
    contents = inpath.read_bytes().strip()

    # logging
    print(f"Read {len(contents)} bytes from {inpath}")

    # decode input from base64
    if read_base64:
        contents = base64.b64decode(contents)

    # encrypting/decrypting
    result = xorcipher(contents)

    # encode result into base64
    if write_base64:
        result = base64.b64encode(result)

    # write output to file
    outpath.write_bytes(result)

    # logging
    print(f"Wrote {len(result)} bytes to {outpath}")

    # OK
    return 0


parser = argparse.ArgumentParser(description="Helper script for Abel's xor chiper.")

# whether to read in base64 or not
parser.add_argument(
    "--read-base64",
    dest="read_base64",
    action="store_true",
    default=False,
    help="If true, decodes the input file using base64. Default is false.",
)

# whether to output in base64 or not
parser.add_argument(
    "--write-base64",
    dest="write_base64",
    action="store_true",
    default=False,
    help="If true, encodes the output using base64. Default is false.",
)

# the input file
parser.add_argument(
    "-f",
    "--input",
    dest="in_file",
    type=str,
    help="The input file.",
)

# the output file
parser.add_argument(
    "-o",
    "--output",
    dest="out_file",
    type=str,
    help="The output file.",
)

if __name__ == "__main__":
    args = parser.parse_args()
    sys.exit(
        main(
            args.in_file,
            args.out_file,
            args.read_base64,
            args.write_base64,
        )
    )
