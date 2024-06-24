# Linux shellcoding ideas for Binary Golfing
It is June 2024, and [Binary Golf](https://binary.golf/) season is upon us!  
For the uninitiated - the idea of Binary Golf is to create the shortest program\script\whatever that does *some task*, where the task changes each time.  
This is [year 5](https://binary.golf/5/), and the goal is:

```
Create the smallest file that downloads [this](https://binary.golf/5/5) text file and displays its contents.
```
(The `this` part is really [https://binary.golf/5/5](https://binary.golf/5/5)).

There are some interesting clarifying questions that were kind of answered:
- It's okay to rely on external dependencies of the OS.
- Environment variables or commandline arguments are okay, although they might be in different categories.

## Preliminary thoughts
Some ideas that come to mind:
1. The URL is `https`, and implementing your own TLS library (or borrowing one) would increase solution size drastically. Therefore, relying on external binaries or libraries makes sense.
2. The `curl` binary exists in every primary modern OS (Windows, Linux, macOS).
3. The URL path could be shortened easily (e.g. like using `bit.ly`).
4. We could send the URL in a commandline argument (or environment variable), or even an entire program!

To test some of those ideas (some of them "game the system" by definition) I submitted [one exterme solution](https://github.com/binarygolf/BGGP/blob/main/2024/entries/jbo/jbo.sh.txt) with only 2 bytes:

```shell
$1
```

To run: `bash jbo.sh "curl https://binary.golf/5/5"`.

In my opinion, this is definitely cheating, but whatever. My real goal is not to rely on scripting but to do some binary work, and so I've decided to go for a shellcode!

## Shellcode ideas
For now I've decided to perform a Linux shellcode, since they're much easier. Also, I really wanted to rely on `curl`.  
I already found one shortened URL that someone submitted, so I'll just use it: `7f.uk`.  
Now, two ideas come to mind for calling `curl`:
1. Find the `system` API in `libc` in some way and run `curl -L 7f.uk`.
2. Call `execve` using a `syscall`.

### Finding libc!system using TSX-based egg-hunting
Normally, before things like [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization), you could rely on the `libc` library to be loaded at a constant address.  
These days `libc` is going to be loaded at a random address, so we have to find it (just like in a real exploit). How does one find `libc` using a shellcode?  
Also, let's keep in mind different `libc` versions might have the `system` symbol live in different offsets, and I wanted to be as generic as possible.  
Well, I've decided to borrow an idea from [Dan Clemente's blogpost on TSX-based egg-hunting](https://bugnotfound.com/posts/htb-business-ctf-2024-abusing-intel-tsx-to-solve-a-sandbox-challenge/).  
Dan has done an awesome work during [HTB Business CTF 2024](https://ctf.hackthebox.com/event/details/htb-business-ctf-2024-the-vault-of-hope-1474) but here's the gist of it:
- Intel [TSX](https://en.wikipedia.org/wiki/Transactional_Synchronization_Extensions) is an extension to the Intel ISA that supports transactional memory.
- The idea is to find a "pattern" in the entire memory by capturing bad memory access using the `xbegin` and `xend` instructions.

So, the first question I had was whether there's a unique pattern in `libc!system` that I could find. Well, as it turns out, `4 bytes` were enough to find it!  
I've done the following:
1. Using the `nm` binary I've listed the symbols in `libc` to find the offset of `system`.
2. I opened the `libc.so.6` library and read all its bytes, and then by brute-force I looked for a unique pattern - one which only exists in `system`.
3. I decided to look for the unique pattern only until a `RET` (0xC3) instruction, even though it's not entirely necessary.
4. I save the offset and the pattern.

As it turns out, the pattern `FF 74 07 E9` is found `6 bytes` inside `libc!system`. Here's some code that finds it:

```python
#!/usr/bin/env python3
import subprocess
import binascii

# Constants
NM_PATH = '/usr/bin/nm'
LIBC_PATH = '/usr/lib/x86_64-linux-gnu/libc.so.6'
SYSTEM_SYMBOL_PATTERN = 'system@@'
RET_INST = b'\xC3'
UNIQUE_PATTERN_LEN = 4

def get_system_pattern_with_offset():
    """
        Finds a unique pattern in libc!system API.
        Returns the tuple: (pattern, pattern_offset_from_system, system_offset_from_libc)
    """

    # Get the system symbol offset
    proc = subprocess.run([ NM_PATH, '-D', LIBC_PATH ], capture_output=True)
    system_offsets = set([ int(line.split(' ')[0], 16) for line in proc.stdout.decode().split('\n') if SYSTEM_SYMBOL_PATTERN in line ])
    if len(system_offsets) == 0:
        raise Exception('Cannot find libc offsets')
    if len(system_offsets) > 1:
        raise Exception('Ambiguity in libc offsets')
    system_offset = system_offsets.pop()
    print(f'[+] Found libc!system offset at 0x{system_offset:02x}')

    # Read libc bytes
    with open(LIBC_PATH, 'rb') as fp:
        libc_bytes = fp.read()

    # Get the system API bytes
    system_bytes = libc_bytes[system_offset:]
    first_ret_index = system_bytes.find(RET_INST)
    if first_ret_index < 0:
        raise Exception('Could not find RET instruction')
    system_bytes = system_bytes[:first_ret_index+1]

    # Find unique bytes in system
    found_pattern = False
    for i in range(len(system_bytes) - UNIQUE_PATTERN_LEN):
        pattern = system_bytes[i:i+UNIQUE_PATTERN_LEN]
        if libc_bytes.find(pattern) < system_offset:
            continue
        if libc_bytes.rfind(pattern) > system_offset + len(system_bytes):
            continue
        found_pattern = True
        break

    # Validate we found a pattern
    if not found_pattern:
        raise Exception('Could not find unique byte pattern')
    pattern_location = system_bytes.find(pattern)
    print(f'[+] Found unique pattern "{binascii.hexlify(pattern)}" {pattern_location} bytes into libc!system')

    # Return data
    return (pattern, pattern_location, system_offset)
```

So, my shellcode is quite simple, even though I saw one issue when calling `libc!system` - it saves MMX registers on the stack, which means we have to keep the stack 16-bytes aligned! Therefore:
1. My shellcode will align the stack to 16-bytes.
2. My shellcode will initialize `RSI` and look for the unique pattern (saved in `ECX`) between `xbegin` and `xend` - bad memory access will roll to the *relative* address mentioned in `xbegin`, which suits shellcodes well.
3. Once pattern is found - use the offset to point `RSI` to `libc!system`.
4. Prepare the sole argument in `RDI` by using `call-pop`.

So, here's my shellcode (I use [nasm](https://nasm.us/)):

```assembly
[BITS 64]

; Constants acquired from preparation
UNIQUE_PATTERN_BYTES EQU 0xe90774ff
SYSTEM_OFFSET_FROM_LIBC EQU 0x50d70
PATTERN_OFFSET_FROM_SYSTEM EQU 0x06

        ; Make some stack is 16-byte aligned
        and rsp, 0xFFFFFFFFFFFFFFF0

        ; Egg-hunting the unique bytes
        mov rsi, SYSTEM_OFFSET_FROM_LIBC + PATTERN_OFFSET_FROM_SYSTEM
        mov ecx, UNIQUE_PATTERN_BYTES

        mov rsi, 0x700007c50d76-0x10000
egg_hunt:
        add rsi, 0x1000
        xbegin egg_hunt
        cmp ecx, [rsi]
        xend
        jne egg_hunt

        ; Point to libc!system
        sub rsi, PATTERN_OFFSET_FROM_SYSTEM

        ; Push the commandline
        call call_system
        db 'curl -L 7f.uk', 0

call_system:
        pop rdi
        call rsi

; Hang
jmp $
```

The terms didn't mention whether the program should exist or not - for all means and purposes I could've let it crash, but I've decided to hang forver using `jmp $`.  
With that, I got a shellcode of `72 bytes`.

###



