void main() {
    int c[60];
    
    for(;;) {
      asm("brk #0;");
      c[9] = 0x42;
      c[10] = 0x41 + c[9];
      asm("brk #0;");
    }
}
