# Self Modifying Code

This binary, at runtime, decodes a base64 encoded payload which contains the
true code of one of its functions to where it belongs, then calls said
function.

## Process

The idea is, since that all calls on amd64 are position-relative, meaning,
there is no absolute address that `call` calls, I need to work with the linker,
in order to do what I want.

The goal is to have the linker do everything for us, so we can: grab the code,
encode it, store it somewhere, unpack it at runtime and execute it. We
absolutely require the linker to calculate where the functions are to be placed
and the proper calculation of `jmp` and `call` instructions.

The process is as such:

1. compile the code into object files as you would normally,
1. create blobs of text that serve as placeholders or "code caves" where the encoded function will live,
1. link everything together with those code caves existing in their own custom sections,
1. open this *intermediate* file and dump the functions' size and instructions,
1. take the instructions and encode them into base64 and overwrite the beginning `n` bytes of a code cave to essentially sneak in the payload into the program,
1. recompile the program,
1. overwrite the functions with `nop` instructions, or some other junk, and finally,
1. serve

>The alignment of code caves is important because if you change the size of the
>code cave between compilations, you could potentially alter the call offsets,
>resulting in a potentially unusable binary.

Your program however, must natually expect these functions to be junk or
could potentially crash the program, therefore you must implement the decoding
routine in the binary and ensure that the function isn't junk before calling
it.
