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
_syms := obscure
syms := $(patsubst %, %.sym, $(_syms))

# sources
src := smodify.c

# objects
obj := $(patsubst %.c, $(objdir)/%.o, $(src))

# blobs for obscuring/linking
blob := $(patsubst %.sym, $(blobdir)/%.blob, $(syms))
embeds := $(patsubst %.sym, $(packeddir)/%.em, $(syms))
packed := $(patsubst %.sym, $(packeddir)/%.packed, $(syms))

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
cxxflags := $(sec_flags) -I. -O1 -fvisibility=default

# linker flags
ldflags := -Wl,-z,relro,-z,now -Wl,-z,noexecstack -lssl -lcrypto -ldl -Wl,-Tlinker.ld -rdynamic

# --- flags ---

# main build target
all: $(prog)
.PHONY: all clean
.PRECIOUS: $(blobdir)/%.sym $(packeddir)/%.em

# compiling regular objects
$(objdir)/%.o: %.c | $(objdir)
	@echo "Compiling $<"
	gcc $(cxxflags) -c $< -o $@

# rule for creating syms
$(blobdir)/%.sym: | $(blobdir)
	$(eval FILE := $(patsubst $(blobdir)/%.sym,$(blobdir)/%, $@))
	$(eval SYM := $(patsubst $(blobdir)/%.sym,%, $@))
	@echo "Creating blob $@ for sym $(SYM)"
	python helper.py --prep -a $(ALIGN) -o $@

# rule for creating blobs
$(blobdir)/%.blob: $(blobdir)/%.sym | $(blobdir)
	@echo "Making blob $< embeddable (target $@)"
	ld -r -b binary -o $@ $<

	@echo "Renaming sections for blob $@"
	objcopy \
		--redefine-sym _binary_obj_blobs_$(SYM)_sym_start=__$(SYM)_start \
		--redefine-sym _binary_obj_blobs_$(SYM)_sym_end=__$(SYM)_end \
		--rename-section .data=.$(SYM) \
		$@

# creating packed objects from blobs
$(packeddir)/%.em: $(blobdir)/%.sym | $(packeddir) $(semi-prog)
	$(eval SYM := $(patsubst $(blobdir)/%.sym,%, $<))
	@echo "Creating packed object $@ from $<"
	python helper.py --embed \
		-f $(semi-prog) \
		-o $@ \
		--symbol $(SYM) \
		--align $(ALIGN) \
		--blob $<

# creating packed objects from blobs
$(packeddir)/%.packed: $(packeddir)/%.em | $(packeddir) $(semi-prog)
	$(eval SYM := $(patsubst $(packeddir)/%.em,%, $<))
	@echo "Making packed code $< embeddable (target $@)"
	ld -r -b binary -o $@ $<

	@echo "Renaming sections for packed blob $@"
	objcopy \
		--redefine-sym _binary_obj_packed_$(SYM)_em_start=__$(SYM)_start \
		--redefine-sym _binary_obj_packed_$(SYM)_em_end=__$(SYM)_end \
		--rename-section .data=.$(SYM) \
		$@

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
	rm -rf $(objdir) *.o *.dep *.debug $(prog) core*
