### Binary Exploitation Mitigations and Attacks

Binary exploitation involves manipulating compiled programs to achieve unintended behavior, often bypassing security mitigations. This guide covers key mitigations, their absence's attack implications, and examples. Useful for CTF pwn challenges.

-----

### PIE (Position Independent Executable)

PIE allows binaries to load at random memory addresses, complicating exploit development by making addresses unpredictable.

  * **If Disabled**: Fixed addresses enable reliable exploits.
  * **Possible Attacks**:
    * **ret2libc**: Overwrite return address to libc functions.
    * **ret2win**: Jump to win functions.
    * **ROP/JOP**: Chain gadgets for arbitrary execution.
  * **Example Exploit**: Fixed base address allows hardcoded ROP chains.

-----

### RELRO (Relocation Read-Only)

RELRO protects GOT/PLT from writes after loading. Partial RELRO offers limited protection.

  * **If Disabled/Partial**: GOT/PLT writable.
  * **Possible Attacks**:
    * **GOT Overwrite**: Hijack function calls.
    * **PLT Hijacking**: Redirect imports.
  * **Example**: Overwrite `printf` GOT entry to `system` for shell.

-----

### Stack Canary

Canary is a random value on stack to detect overflows, protecting return addresses.

  * **If Disabled**: No overflow detection.
  * **Possible Attacks**:
    * **Stack Buffer Overflow**: Overwrite EIP/EBP.
    * **Shellcode Injection**: Execute on stack.
    * **ROP/ret2libc**: Unrestricted chaining.
  * **Bypass**: Leak canary via format strings, then overflow.

-----

### NX (No eXecute)

NX marks stack/heap non-executable, preventing shellcode execution.

  * **If Disabled**: Executable stack/heap.
  * **Possible Attacks**:
    * **Shellcode Execution**: Inject and run code.
    * **Stack Smashing**: Direct exploits.
  * **Bypass**: Use ROP to execute existing code.

-----

### RWX Segments (Read-Write-Execute)

RWX allows read/write/execute on memory regions, ideal for injection.

  * **If Enabled**: Easy code injection.
  * **Possible Attacks**:
    * **Direct Injection**: Write shellcode to RWX memory.
    * **Overwrite Execution**: Modify and run.
  * **Mitigation**: Use separate permissions (e.g., RW vs. RX).

---

### Stripped / Not Stripped

Stripped binaries lack symbols, hindering analysis.

  * **If Not Stripped**: Symbols present.
  * **Possible Attacks**:
    * **Easier RE**: Identify functions quickly.
    * **ROP Planning**: Gadget enumeration.
    * **Win Function Discovery**: Find hidden functions.
  * **Tools**: Use `nm` or IDA for non-stripped binaries.

### Other Vectors

  * **Heap Exploits**: UAF, overflows if NX/RELRO weak.
  * **Format Strings**: If printf vulnerable, leak/stack writes.
  * **Arbitrary Writes**: Overwrite pointers for control.

-----

### Checking Mitigations

Use `checksec` (pwntools):

```bash
checksec binary
```

Output shows PIE, RELRO, Canary, NX status.

-----

### Example Exploit (ret2libc without PIE/Canary)

```python
from pwn import *

p = process('./binary')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Leak libc base
payload = b'A' * 72 + p64(0x400600)  # pop rdi; ret
p.sendline(payload)
leak = p.recv()
libc.address = leak - libc.sym['puts']

# ret2libc
payload = b'A' * 72 + p64(libc.address + 0x4f2c5)  # one_gadget
p.sendline(payload)
p.interactive()
```

-----

**Made with love by VIsh0k**