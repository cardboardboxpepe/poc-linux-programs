# Ghidra & Malware Analysis

The workshop about malware analysis and an intro to Ghidra, presented by Liam M.

## How does it work?

The program (`cain.c`) self extracts another program (`able.c`) from inside
itself and calls a flag checker function. This function simply converts input
into base64 against the flag that's also encoded into base64.

To prevent a simple analysis via `strings`, the flag is also encrypted using a
simple xor cipher. This is so that the participants must actually reverse
engineer the binary in order to figure out what it does.
