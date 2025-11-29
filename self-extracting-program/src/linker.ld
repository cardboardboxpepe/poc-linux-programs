ENTRY(_start)

SECTIONS {
  . = SIZEOF_HEADERS;

  .dynamic : ALIGN(0x1000) {
    *(.dynamic)
  }
  
  .dynsym : ALIGN(0x1000) {
    *(.dynsym)
  }
  
  .plt : ALIGN(0x1000) {
    *(.plt)
  }

  .rela.plt : ALIGN(0x1000) {
    *(.rela.plt)
  }

  /* Code section */
  .text : ALIGN(0x1000) {
    *(.text)
  }

  /* space for libabel */
  .libabel : ALIGN(4) {
    *(.libabel)
  }

  /* BSS section */
  .bss : ALIGN(0x1000) {
    *(.bss)
  }

  /* this stores our hooks into the text section */
  .rodata : ALIGN(0x1000) {
    __text_start = ADDR(.text);
    __text_end = ADDR(.text) + 0x3000;
  }

  /* Read-write data section */
  .data : ALIGN(0x1000) {
    *(.data)
  }
}
