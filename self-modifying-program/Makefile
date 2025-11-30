# --- cmd args ---

ifeq ($(origin MAKEROOT), undefined)
MAKEROOT = $(shell realpath ../..)
endif

# --- cmd args ---
# --- directories ---

# directories
objdir := obj
libdir := lib
blobdir := $(objdir)/blobs
packeddir := $(objdir)/packed

# --- directories ---
# --- challenge stuff ---

# file alignment
ALIGN := 1024

# the symbol to obscure
syms := obscure

# sources
src := smodify.c

# objects
obj := $(patsubst %.c, $(objdir)/%.o, $(src))

# blobs for obscuring/linking
blob := $(patsubst %, $(blobdir)/%.blob, $(syms))
packed := $(patsubst %, $(packeddir)/%.packed, $(syms))

# --- files ---
# --- build requirements ---

# requirements for the main program
program-requirements := $(obj) $(blob)
final-program := $(obj) $(packed)

# the target build object
semi-prog := smodify.semi
prog := smodify.bin

# --- build requirements ---
# --- flags ---

# flags
sec_flags := -fstack-protector-strong
cxxflags := $(sec_flags) -I. -ggdb3 -g -O0 -DDEBUG=1 -D_DEBUG=1 -fvisibility=default -fno-PIC

# linker flags
ldflags := -no-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -lssl -lcrypto -ldl -Wl,-Tlinker.ld

# --- flags ---

# main build target
all: $(prog)
.PHONY: all clean

# compiling regular objects
$(objdir)/%.o: %.c | $(objdir)
	@echo "Compiling $<"
	gcc $(cxxflags) -c $< -o $@

# rule for creating blobs
$(blobdir)/%.blob: | $(blobdir)
	$(eval FILE := $(patsubst $(blobdir)/%.blob,$(blobdir)/%, $@))
	$(eval SYM := $(patsubst $(blobdir)/%.blob,%, $@))
	@echo "Creating blob $@ for sym $(SYM)"
	python helper.py --prep -a $(ALIGN) -o $(FILE)

	@echo "Making blob $@ embeddable"
	ld -r -b binary -o $@ $(FILE)

	@echo "Renaming sections for blob $@"
	objcopy \
		--redefine-sym _binary_obj_blobs_$(SYM)_start=__$(SYM)_start \
		--redefine-sym _binary_obj_blobs_$(SYM)_end=__$(SYM)_end \
		--rename-section .data=.$(SYM) \
		$@
# cleanup
	@rm $(FILE)

# creating packed objects from blobs
$(packeddir)/%.packed: $(blobdir)/%.blob | $(packeddir) $(semi-prog)
	@echo "Creating packed object $@ from $<"
	cp $< $@

# creating the intermediate program
$(semi-prog): $(obj) $(blob)
	@echo "Creating the intermediate program"
	gcc -o $@ $^ $(ldflags)

$(prog): $(obj) $(packed) | $(semi-prog)
	@echo "Creating the final program"
	gcc -o $@ $^ $(ldflags)

# making directories
$(objdir):
	@mkdir -p $@
$(blobdir):
	@mkdir -p $@
$(packeddir):
	@mkdir -p $@

clean:
	rm -rf $(objdir) *.o *.dep *.debug $(prog)
