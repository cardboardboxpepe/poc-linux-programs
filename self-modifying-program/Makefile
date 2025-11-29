# --- cmd args ---

ifeq ($(origin MAKEROOT), undefined)
MAKEROOT = $(shell realpath ../..)
endif

# --- cmd args ---
# --- directories ---

# directories
objdir := obj
libdir := lib

# --- directories ---
# --- challenge stuff ---

# sources
src := symlookup.c

obj := $(patsubst %.c, $(objdir)/%.o, $(src))
obj_debug := $(patsubst %.c, $(objdir)/%.o.debug, $(src))

# flags
sec_flags := -fstack-protector-strong
cxxflags := $(sec_flags) -I. -ggdb3 -g -O0 -DDEBUG=1 -D_DEBUG=1 -fvisibility=default -fno-PIC

# linker flags
ldflags := -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -lssl -lcrypto -ldl -rdynamic

# --- challenge stuff ---
# --- build requirements ---

prod_req := $(obj)

# the target build object
prog := symlookup.bin

# --- build requirements ---

# main build target
all: $(prog)
.PHONY: all clean

$(prog): $(prod_req)
	@echo "Linking everything together"
	gcc -o $@ $^ $(ldflags)

# making directories
$(objdir):
	@mkdir -p $@/src

# compiling regular objects
$(objdir)/%.o: %.c | $(objdir)
	@echo "Compiling $<"
	gcc $(cxxflags) -c $< -o $@

clean:
	rm -rf $(objdir) *.o *.dep *.debug $(prog)
