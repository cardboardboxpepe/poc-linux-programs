.PHONY: all clean

# flags for object copying
objcopyflags=-w -x -X -g

# directory for object files
objdir = objs

# directory for libraries
libdir = libs

# directory for embedded files
emdir = embed

# --- embedded object sources ---

# the sources of our embedded files
abel_src = abel.c base64.c
abel_func = check # the main function that abel exports

# object files
abel_obj = $(patsubst %.c, $(objdir)/%.o, $(filter %.c, $(abel_src)))

# shared objects
abel_so = $(libdir)/libabel.so

# embedded files
abel_embed = $(patsubst $(libdir)/lib%.so, $(emdir)/%.em, $(abel_so))

# all source files for compiling
abel_depends = $(abel_obj) $(abel_so) $(abel_embed)

# --- embedded object sources ---
# --- cain sources ---

cain_src = cain.c base64.c
cain_obj = $(patsubst %.c, $(objdir)/%.o, $(cain_src))
cain_prog = cain

# --- cain sources ---

# compilation flag
DEBUGLEVEL=0
DEBUGSW=-DDEBUG=$(DEBUGLEVEL) -D_DEBUG=$(DEBUGLEVEL)
DEBUGFLAGS=$(DEBUGSW) -fno-omit-frame-pointer -g -ggdb3
CXXFLAGS=$(DEBUGSW) -O2 -D_GNU_SOURCE -fPIC -I. -fno-omit-frame-pointer -fstack-protector-all -Wno-unused-result
LDFLAGS=-lssl -lcrypto -ldl -Wl,-z,noexecstack -Wl,-z,relro,-z,now

# all files for cleanup
all_files = $(abel_depends) $(cain_obj) $(cain_prog)
compilation = $(abel_embed) $(cain_obj)

# main build target
all: $(cain_prog)
files: $(all_files)
.PRECIOUS: $(all_files)

# making directories
$(libdir):
	@mkdir -p $@
$(objdir):
	@mkdir -p $@
$(emdir):
	@mkdir -p $@

# rule for compiling every object file
$(objdir)/%.o: %.c | $(objdir)
	@echo "Compiling $< into pie code"
	gcc $(CXXFLAGS) -c $< -o $@

# rule for compiling libabel
$(abel_so): $(abel_obj) | $(libdir)
	@echo "Compiling libabel from $^ to $@"
	gcc $(CXXFLAGS) \
		-s \
		-Wl,--require-defined=$(abel_func) \
		-shared -o temp.so $^

	@echo "Removing sections and symbols (again)"
	objcopy $(objcopyflags) \
		--keep-symbol=$(abel_func) \
		--strip-all \
		--remove-section=.comment \
		--remove-section=.note.* \
		temp.so $@

	@echo "Linked $^ to $@"
	@rm temp*

# I hate this
$(emdir)/%.em: $(libdir)/lib%.so | $(emdir)
	@echo "Transforming $< to be embeddable"
	ld -r -b binary -o $@ $<

	@echo "Renaming section from .data to .$(patsubst $(libdir)/lib%.so,lib%, $<) for embedding"
	objcopy \
		--redefine-sym _binary_libs_$(patsubst $(libdir)/lib%.so,lib%, $<)_so_start=__$(patsubst $(libdir)/lib%.so,lib%, $<)_start \
		--redefine-sym _binary_libs_$(patsubst $(libdir)/lib%.so,lib%, $<)_so_end=__$(patsubst $(libdir)/lib%.so,lib%, $<)_end \
		--rename-section .data=.$(patsubst $(libdir)/lib%.so,lib%, $<) \
		$@

# rule for compiling cain
$(cain_prog): $(compilation)
	@echo "Linking everything together: $^"
	gcc $(LDFLAGS) -s -Wl,-Tlinker.ld -o temp $^

	@echo "Removing sections"
	objcopy \
		--remove-section=.comment \
		--remove-section=.note.* \
		temp $@

	@echo "Compiled $@ from $^"
	@rm temp

clean:
	rm $(all_files) *.so* *.s *.o *.syms $(objdir)/*.ob *.exe *.bin || true
	rm -rf $(objdir) $(emdir) $(libdir) || true
