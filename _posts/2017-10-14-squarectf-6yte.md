---
layout: post
title: "SquareCTF 6yte writeup"
categories: blog writeups re
---

I should start this post by saying that I’m _very_ new to CTFs, and even newer
to reverse engineering. Since I’m currently blessed with an abundance of spare
time I figured I may as well use it somewhat productively.

SquareCTF is a security CTF hosted by [Square, Inc](https://squareup.com/). In
this blog-post I will be doing a write-up of their 6yte challenge - a
reverse-engineering challenge.

## The challenge

The user is given the following blurb:

> Our operatives found this site, which appears to control some of the androids’
infrastructure! There are only two problems. The robots love x86 assembly; the
only thing easier for them to work with is binary. And they love terse command
codes. Even 7 bytes was too many for this one.

> This URL is unique to your team! Don’t share it with competitors! <– URL
REDACTED –>

On accessing the URL, the user is provided with a link to the binary (viewers
playing along at home can download it
[here]({{"/assets/6yte" | absolute_url}})), as well as some more
information about the challenge:

> You can send up to 6 bytes (hex encoded) as the first argument to the binary.
The passed in bytes will be executed. The goal is to read the contents of the
file in env[‘WUNTEE_CHALLENGE_FLAG’].

At the bottom of the page is a text box into which you can enter the argument
(in the form of a hex string) and execute the program on their server. So
whatever reversing we manage to do, we’ll have to enter the fruits of our labour
here and hopefully be rewarded with a flag.

## The binary

`file` tells us the binary is a 32-bit ELF binary.

We’re told we need to provide an argument to it, but I’m not going to bother to
start off with. However, what we do need to provide is an environment variable
which will hopefully point to a file that contains the flag.

```
-> % WUNTEE_CHALLENGE_FLAG=testing ./6yte         
The input you provided was bad.
```

Oh huh… I guess we _do_ need to give it an argument.

```
-> % WUNTEE_CHALLENGE_FLAG=testing ./6yte f0f0f0f0f0f0
Shellcode location: 0xf77c2000
Flag location: 0xffa447b0
Could not read file.
```

Of course, we never created a flag file for it to read from. Let’s create a
dummy flag file and see if the same thing happens again.

```
-> % echo 'flag-pwn3d' > testing
-> % WUNTEE_CHALLENGE_FLAG=testing ./6yte f0f0f0f0f0f0
Shellcode location: 0xf772e000
Flag location: 0xff875850
[1]    6475 segmentation fault  WUNTEE_CHALLENGE_FLAG=testing ./6yte f0f0f0f0f0f0
```

Cool, we’ve got to a point where it’s probably trying to run the code that we
provided. It also provides us some memory addresses that look very useful.
Subsequent invocations change those addresses - I’m guessing we can’t just write
some shellcode that prints data at a static memory address.

```
-> % WUNTEE_CHALLENGE_FLAG=testing ./6yte f0f0f0f0f0f0
Shellcode location: 0xf76f4000
Flag location: 0xff9eb700
[1]    17272 segmentation fault  WUNTEE_CHALLENGE_FLAG=testing ./6yte f0f0f0f0f0f0
```

Ok, let’s get [radare2](http://rada.re/r/) booted and take a deeper look. One
thing I noticed is that sometimes when providing arguments to the binary when
invoking via r2 is that you get weird errors. If anyone knows why this is,
please let me know. So I just re-open with `doo ARGS` after invoking r2.

```
-> % WUNTEE_CHALLENGE_FLAG=testing radare2 -wd ./6yte
Process with PID 3109 started...                     
= attach 3109 3109
bin.baddr 0x08048000
USING 8048000
Assuming filepath /home/martin/6yte
asm.bits 32
[0xf77bba20]> doo f0f0f0f0f0f0
```

Whenever I open a binary, the first thing I do is run `aaa` to invoke ~magic~,
which lets me find out what functions the binary has, etc. We can then list
these functions with `afl`.

```
[0xf77a4a20]> aaa
[ ] Analyze all flags starting with sym. and entry0 (a[x] Analyze all flags starting with sym. and entry0 (aa)
[ ] Analyze len bytes of instructions for references ([Cannot determine xref search boundaries
[x] Analyze len bytes of instructions for references (aar)
[Oops invalid rangen calls (aac)
[x] Analyze function calls (aac)
[ ] [*] Use -AA or aaaa to perform additional experimental analysis.
[[ ] Constructing a function name for fcn.* and sym.fu[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[0xf77a4a20]> afl
0x080484a4    3 35           sym._init
0x080484e0    1 6            sym.imp.printf
0x080484f0    1 6            sym.imp.fgets
0x08048500    1 6            sym.imp.fclose
0x08048510    1 6            sym.imp.sleep
0x08048520    1 6            sym.imp.alarm
0x08048530    1 6            sym.imp.getenv
0x08048540    1 6            sym.imp.puts
0x08048550    1 6            loc.imp.__gmon_start__
0x08048560    1 6            sym.imp.exit
0x08048570    1 6            sym.imp.mmap
0x08048580    1 6            sym.imp.__libc_start_main
0x08048590    1 6            sym.imp.__isoc99_sscanf
0x080485a0    1 6            sym.imp.setvbuf
0x080485b0    1 6            sym.imp.fopen
0x080485c0    1 6            sym.imp.strnlen
0x080485d0    1 33           entry0
0x08048600    1 4            sym.__x86.get_pc_thunk.bx
0x08048610    4 43           sym.deregister_tm_clones
0x08048640    4 53           sym.register_tm_clones
0x08048680    3 30           sym.__do_global_dtors_aux
0x080486a0    4 43   -> 40   sym.frame_dummy
0x080486cb    1 32           sym.bad_input
0x080486eb    5 154          sym.read_flag
0x08048785    9 359          sym.main
0x08048900    4 97           sym.__libc_csu_init
0x08048970    1 2            sym.__libc_csu_fini
0x08048974    1 20           sym._fini
[0xf77a4a20]> 
```

There’s a few imported functions here you’d expect to see (`printf`, `puts`,
etc.). You can also see `mmap`, which I’m guessing is used to write ARGV[1] to
some block of memory.

The first thing we need to do is take a look at the disassembly of `main()`. In
radare2, this is simple; we use `pdf @sym.main` - which roughly translates to
‘[p]rint [d]isassembly of the [f]unction @ sym.main’.

```
[0xf7712a20]> pdf @sym.main
;-- main:
/ (fcn) sym.main 359
|   sym.main ();
|     ; var int local_8ch @ ebp-0x9c
|     ; var int local_98h @ ebp-0x98
|     ; var int local_18h @ ebp-0x18
|     ; var int local_14h @ ebp-0x14
|     ; var int local_10h @ ebp-0x10
|     ; var int local_ch @ ebp-0xc
|     ; var int local_4h @ esp+0x4
|     ; DATA XREF from 0x080485e7 (entry0)
|     0x08048785      8d4c2404       lea ecx, dword [esp + local_4h] ; 0x4 ; 4
|     0x08048789      83e4f0         and esp, 0xfffffff0
|     0x0804878c      ff71fc         push dword [ecx - 4]
|     0x0804878f      55             push ebp
|     0x08048790      89e5           mov ebp, esp
|     0x08048792      53             push ebx
|     0x08048793      51             push ecx
|     0x08048794      81eca0000000   sub esp, 0xa0
|     0x0804879a      89cb           mov ebx, ecx
|     0x0804879c      c78564ffffff.  mov dword [ebp - local_9ch], 0
|     0x080487a6      c745ec000000\.  mov dword [ebp - local_14h], 0
|     0x080487ad      a1009d0408     mov eax, dword [obj.stdout] ; [0x8049d00:4]=0 LEA obj.stdout ; obj.stdout
|     0x080487b2      6a00           push 0
|     0x080487b4      6a02           push 2                      ; 2
|     0x080487b6      6a00           push 0
|     0x080487b8      50             push eax
|     0x080487b9      e8e2fdffff     call sym.imp.setvbuf       ; int setvbuf(FILE*stream, char*buf, int mode, size_t size);
|     0x080487be      83c410         add esp, 0x10
|     0x080487c1      a1e09c0408     mov eax, dword [obj.stderr] ; [0x8049ce0:4]=0 LEA obj.stderr ; obj.stderr
|     0x080487c6      6a00           push 0
|     0x080487c8      6a02           push 2                      ; 2
|     0x080487ca      6a00           push 0
|     0x080487cc      50             push eax
|     0x080487cd      e8cefdffff     call sym.imp.setvbuf       ; int setvbuf(FILE*stream, char*buf, int mode, size_t size);
|     0x080487d2      83c410         add esp, 0x10
|     0x080487d5      83ec0c         sub esp, 0xc
|     0x080487d8      6a07           push 7                      ; 7
|     0x080487da      e841fdffff     call sym.imp.alarm
|     0x080487df      83c410         add esp, 0x10
|     0x080487e2      833b02         cmp dword [ebx], 2          ; [0x2:4]=-1 ; 2
| ,=< 0x080487e5      7405           je 0x80487ec
| |   0x080487e7      e8dffeffff     call sym.bad_input
| `-> 0x080487ec      8b4304         mov eax, dword [ebx + 4]    ; [0x4:4]=-1 ; 4
|     0x080487ef      83c004         add eax, 4
|     0x080487f2      8b00           mov eax, dword [eax]
|     0x080487f4      83ec08         sub esp, 8
|     0x080487f7      6aff           push -1
|     0x080487f9      50             push eax
|     0x080487fa      e8c1fdffff     call sym.imp.strnlen
|     0x080487ff      83c410         add esp, 0x10
|     0x08048802      8945ec         mov dword [ebp - local_14h], eax
|     0x08048805      837dec0c       cmp dword [ebp - local_14h], 0xc ; [0xc:4]=-1 ; 12
| ,=< 0x08048809      770a           ja 0x8048815
| |   0x0804880b      8b45ec         mov eax, dword [ebp - local_14h]
| |   0x0804880e      83e001         and eax, 1
| |   0x08048811      85c0           test eax, eax
|,==< 0x08048813      7405           je 0x804881a
||`-> 0x08048815      e8b1feffff     call sym.bad_input
|`--> 0x0804881a      83ec08         sub esp, 8
|     0x0804881d      6a00           push 0
|     0x0804881f      6aff           push -1
|     0x08048821      6a21           push 0x21                   ; '!' ; '!' ; 33
|     0x08048823      6a07           push 7                      ; 7
|     0x08048825      6a06           push 6                      ; 6
|     0x08048827      6a00           push 0
|     0x08048829      e842fdffff     call sym.imp.mmap
|     0x0804882e      83c420         add esp, 0x20
|     0x08048831      8945e8         mov dword [ebp - local_18h], eax
|     0x08048834      c745f0000000\.  mov dword [ebp - local_10h], 0
|     0x0804883b      c745f4000000\.  mov dword [ebp - local_ch], 0
| ,=< 0x08048842      eb3d           jmp 0x8048881
|.--> 0x08048844      8b4304         mov eax, dword [ebx + 4]    ; [0x4:4]=-1 ; 4
|||   0x08048847      83c004         add eax, 4
|||   0x0804884a      8b10           mov edx, dword [eax]
|||   0x0804884c      8b45f4         mov eax, dword [ebp - local_ch]
|||   0x0804884f      01c2           add edx, eax
|||   0x08048851      83ec04         sub esp, 4
|||   0x08048854      8d8564ffffff   lea eax, dword [ebp - local_9ch]
|||   0x0804885a      50             push eax
|||   0x0804885b      68188a0408     push 0x8048a18
|||   0x08048860      52             push edx
|||   0x08048861      e82afdffff     call sym.imp.__isoc99_sscanf; int sscanf(const char *s,
|||   0x08048866      83c410         add esp, 0x10
|||   0x08048869      8b55f0         mov edx, dword [ebp - local_10h]
|||   0x0804886c      8b45e8         mov eax, dword [ebp - local_18h]
|||   0x0804886f      01d0           add eax, edx
|||   0x08048871      8b9564ffffff   mov edx, dword [ebp - local_9ch]
|||   0x08048877      8810           mov byte [eax], dl
|||   0x08048879      8345f001       add dword [ebp - local_10h], 1
|||   0x0804887d      8345f402       add dword [ebp - local_ch], 2
|||   ; JMP XREF from 0x08048842 (sym.main)
||`-> 0x08048881      8b45f4         mov eax, dword [ebp - local_ch]
||    0x08048884      3b45ec         cmp eax, dword [ebp - local_14h]
|`==< 0x08048887      72bb           jb 0x8048844
|     0x08048889      83ec08         sub esp, 8
|     0x0804888c      ff75e8         push dword [ebp - local_18h]
|     0x0804888f      681c8a0408     push str.Shellcode_location:__p_n ; str.Shellcode_location:__p_n ; "Shellcode location: %p." @ 0x8048a1c
|     0x08048894      e847fcffff     call sym.imp.printf        ; int printf(const char *format);
|     0x08048899      83c410         add esp, 0x10
|     0x0804889c      83ec08         sub esp, 8
|     0x0804889f      8d8568ffffff   lea eax, dword [ebp - local_98h]
|     0x080488a5      50             push eax
|     0x080488a6      68348a0408     push str.Flag_location:__p_n ; str.Flag_location:__p_n ; "Flag location: %p." @ 0x8048a34
|     0x080488ab      e830fcffff     call sym.imp.printf        ; int printf(const char *format);
|     0x080488b0      83c410         add esp, 0x10
|     0x080488b3      83ec0c         sub esp, 0xc
|     0x080488b6      6a01           push 1                      ; 1
|     0x080488b8      e853fcffff     call sym.imp.sleep         ; int sleep(int s);
|     0x080488bd      83c410         add esp, 0x10
|     0x080488c0      83ec0c         sub esp, 0xc
|     0x080488c3      8d8568ffffff   lea eax, dword [ebp - local_98h]
|     0x080488c9      50             push eax
|     0x080488ca      e81cfeffff     call sym.read_flag         ; ssize_t read(int fildes, void *buf, size_t nbyte);
|     0x080488cf      83c410         add esp, 0x10
|     0x080488d2      8d8568ffffff   lea eax, dword [ebp - local_98h]
|     0x080488d8      89c7           mov edi, eax
|     0x080488da      ba05000000     mov edx, 5
|     0x080488df      bb01000000     mov ebx, 1
|     0x080488e4      b804000000     mov eax, 4
\     0x080488e9      ff65e8         jmp dword [ebp - local_18h]
```

As I said earlier, I’m very new to reverse engineering. But from this
disassembled view, we can see quite a few things that are going on. There’s some
setting up of some registers prior to function calls, the function calls
themselves and, at the end, some jump to another location.

Of interest is the call to `sleep` - I suspect this is implemented to discourage
brute-force attacks of the program. Amusingly, this is an approach I briefly
considered before deciding to stop being lazy and actually reverse the damn
thing.

Oh, as an aside, can we just take a moment to appreciate how beautiful radare2
is? My blog theme loses the colorisation so here’s a screenshot just because I’d
be remiss if I didn’t include it:

![Radare2 disassembly]({{"/assets/radare2disassembly.png" | absolute_url}})

On with the show. The `read_flag` function certainly looks interesting. Let’s
take a look at the disassembly:

```
[0xf7712a20]> pdf @sym.read_flag
/ (fcn) sym.read_flag 154
|   sym.read_flag (int arg_8h);
|    ; var int local_10h @ ebp-0x10
|    ; var int local_ch @ ebp-0xc
|    ; arg int arg_8h @ ebp+0x8
|    ; CALL XREF from 0x080488ca (sym.main)
|    0x080486eb      55             push ebp
|    0x080486ec      89e5           mov ebp, esp
|    0x080486ee      83ec18         sub esp, 0x18
|    0x080486f1      83ec0c         sub esp, 0xc
|    0x080486f4      68b0890408     push str.WUNTEE_CHALLENGE_FLAG ; str.WUNTEE_CHALLENGE_FLAG ; "WUNTEE_CHALLENGE_FLAG" @ 0x80489b0
|    0x080486f9      e832feffff     call sym.imp.getenv        ; char *getenv(const char *name);
|    0x080486fe      83c410         add esp, 0x10
|    0x08048701      8945f4         mov dword [ebp - local_ch], eax
|    0x08048704      837df400       cmp dword [ebp - local_ch], 0
|,=< 0x08048708      751f           jne 0x8048729
||   0x0804870a      83ec08         sub esp, 8
||   0x0804870d      68b0890408     push str.WUNTEE_CHALLENGE_FLAG ; str.WUNTEE_CHALLENGE_FLAG ; "WUNTEE_CHALLENGE_FLAG" @ 0x80489b0
||   0x08048712      68c8890408     push str._s_environmental_variable_not_set._Could_not_read_flag._n ; str._s_environmental_variable_not_set._Could_not_read_flag._n ; "%s environmental variable not set. Could not read flag.." @ 0x80489c8
||   0x08048717      e8c4fdffff     call sym.imp.printf        ; int printf(const char *format);
||   0x0804871c      83c410         add esp, 0x10
||   0x0804871f      83ec0c         sub esp, 0xc
||   0x08048722      6aff           push -1
||   0x08048724      e837feffff     call sym.imp.exit          ; void exit(int status);
|`-> 0x08048729      83ec08         sub esp, 8
|    0x0804872c      68018a0408     push 0x8048a01
|    0x08048731      ff75f4         push dword [ebp - local_ch]
|    0x08048734      e877feffff     call sym.imp.fopen         ; file*fopen(const char *filename,
|    0x08048739      83c410         add esp, 0x10
|    0x0804873c      8945f0         mov dword [ebp - local_10h], eax
|    0x0804873f      837df000       cmp dword [ebp - local_10h], 0
|,=< 0x08048743      751a           jne 0x804875f
||   0x08048745      83ec0c         sub esp, 0xc
||   0x08048748      68038a0408     push str.Could_not_read_file. ; str.Could_not_read_file. ; "Could not read file." @ 0x8048a03
||   0x0804874d      e8eefdffff     call sym.imp.puts          ; int puts(const char *s);
||   0x08048752      83c410         add esp, 0x10
||   0x08048755      83ec0c         sub esp, 0xc
||   0x08048758      6aff           push -1
||   0x0804875a      e801feffff     call sym.imp.exit          ; void exit(int status);
|`-> 0x0804875f      83ec04         sub esp, 4
|    0x08048762      ff75f0         push dword [ebp - local_10h]
|    0x08048765      6880000000     push 0x80                   ; 128
|    0x0804876a      ff7508         push dword [ebp + arg_8h]
|    0x0804876d      e87efdffff     call sym.imp.fgets         ; char *fgets(char *s, int size, FILE *stream);
|    0x08048772      83c410         add esp, 0x10
|    0x08048775      83ec0c         sub esp, 0xc
|    0x08048778      ff75f0         push dword [ebp - local_10h]
|    0x0804877b      e880fdffff     call sym.imp.fclose        ; int fclose(FILE *stream);
|    0x08048780      83c410         add esp, 0x10
|    0x08048783      c9             leave
\    0x08048784      c3             ret
```

We can see a call to `getenv`, and after a `jne` comparing `ebp - localch` with 0.
It looks like this is the check to make sure the environment variable has
been set correctly. By this reasoning, it looks like the filename is stored in
the block of memory pointed at by eax. We can verify this by setting a
breakpoint right at that check and inspecting the registers.

```
[0xf7712a20]> db 0x08048708
[0xf7712a20]> dc
child stopped with signal 28
[+] SIGNAL 28 errno=0 addr=0x00000000 code=128 ret=0
got signal...
= attach 14645 1
[+] signal 28 aka SIGWINCH received 0
[0xf7712a20]> dc
Shellcode location: 0xf7750000
Flag location: 0xffcb2550
hit breakpoint at: 8048708
[0x08048708]>
```

Weird, we hit a signal when we continued the code. I noticed this a few times
while working on this binary, but didn’t seem to find anything interesting as a
result. The program also prints the location of the shellcode and the flag, both
of which will be super useful. More on that later. Anyway, the registers…

```
[0x08048708]> drr
	 eip 0x08048708  (.text) (/home/martin/6yte) eip sym.read_flag program R X 'jne 0x8048729' '6yte'
	oeax 0xffffffff  oeax
	 eax 0xffe89fde  eax stack R W 0x74736574 (testing) --> ascii
	 ebx 0xffe885f0  ebx stack R W 0x2 --> (.comment) esi
	 ecx 0x080489c2  (.rodata) (/home/martin/6yte) ecx program R X 'dec esp' '6yte' (LAG)
	 edx 0xffe89fda  edx stack R W 0x3d47414c (LAG=testing) --> ascii
	 esp 0xffe88500  esp stack R W 0xffe885d8 --> stack R W 0x0 --> section_end.GNU_STACK
	 ebp 0xffe88518  ebp stack R W 0xffe885d8 --> stack R W 0x0 --> section_end.GNU_STACK
	 esi 0x00000002  (.comment) esi
	 edi 0xf76da000  (/lib/i386-linux-gnu/libc-2.24.so) edi library R W 0x1b3db0
	 xfs 0x00000000  section_end.GNU_STACK
	 xgs 0x00000063  (.shstrtab) ascii
	 xcs 0x00000023  (.comment) ascii
	 xss 0x0000002b  (.comment) ascii
eflags       1PSI  (.symtab) eflags
```

Sure enough, looking at the value of `eax`, it contains the ascii string
‘testing’. This might not be too useful now but at least gives us some idea of
how to use radare2 to pause the program and inspect the registers.

After this, the function seems to open the file and read it in to some block of
memory (`fopen`, `fgets` and `fclose`), as well as a few other sanity checks
(e.g., does the file exist? can we open the file?). This is gives us a really
big hint. If the program has written the contents of this file to memory, we
just need to write a piece of shellcode to find where it is in memory and print
it out. Bad news is… how the hell do you do this in a mere 6 bytes?

As previously mentioned, at the end of the `main()`, there’s a `jmp` to some
location. Let’s check that out by setting a breakpoint as we did earlier (`db
0x080488e9`).

```
    [0x080488e9]> drr
       eip 0x080488e9  (.text) (/home/martin/6yte) eip program R X 'jmp dword [ebp - 0x18]' '6yte'
      oeax 0xffffffff  oeax
       eax 0x00000004  (.comment) eax
       ebx 0x00000001  (.comment) ebx
       ecx 0xf7720bcc  (/lib/i386-linux-gnu/libc-2.24.so) ecx library R W 0x21000
       edx 0x00000005  (.comment) edx
       esp 0xffcb2540  esp stack R W 0xf777ca7c --> (/lib/i386-linux-gnu/ld-2.24.so) library R W 0xf7752b18 --> (unk1) R W 0xf777c920 --> (/lib/i386-linux-gnu/ld-2.24.so) library R W 0x0 --> section_end.GNU_STACK
       ebp 0xffcb25e8  ebp stack R W 0x0 --> section_end.GNU_STACK
       esi 0x00000002  (.comment) esi
       edi 0xffcb2550  edi stack R W 0x67616c66 (flag-pwn3d
    ) --> ascii
       xfs 0x00000000  section_end.GNU_STACK
       xgs 0x00000063  (.shstrtab) ascii
       xcs 0x00000023  (.comment) ascii
       xss 0x0000002b  (.comment) ascii
    eflags        1SI  (.symtab) eflags
```

This is exciting! The contents of the flag have been loaded, and `edi` points
right where they are! So rather than having to find and load the flag, we can
just print the contents of `edi` and we should be home-free.

Let’s revisit the memory addresses that were printed earlier, to see if there’s
anything else we can find out. The address printed earlier as the ‘flag
location’ is the same as the address currently stored in `edi`, so no need to
check them out. But how about the address of the shellcode?

```
[0x08048be9]> pxi @0xf7750000
					 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
F7750000: f0 f0 f0 f0 f0 f0
```

Not surprisingly, it’s the hex we provided as ARGV[1]. Let’s step through the
code step-by-step with `ds`.

```
[0x08048be9]> ds
[0xf7750000]> 
```

Oh hello. Look at that. The code’s jumped to the position of the shellcode, that
we saw printed earlier.

As a quick summary then, we can see the program executes as follows (assuming
the environment variable and file are present):

1.  Check that the shellcode provided in ARGV[1] is good (present and the
correct length)
2.  Load ARGV[1] in to memory convert & from a string to binary
3.  Load this binary in to memory
4.  Print the location of the shellcode and the flag
5.  Load the flag in to memory, leaving its location in `edi`
6.  Jump to the location of the shellcode and execute

So, in order to win the flag, all we need to do is find some way to print the
segment of memory pointed at by `edi`. For a while, I played around trying to
invoke one of the earlier calls to `puts` (first pushing `edi` to the stack).
This unfortunately didn’t seem to work - I just repeatedly got segfaults and
headaches.

After reading a few posts from other CTFs and low-level printing to the
terminal, I found that it could be done in very few instructions by using a
syscall to `write()`. I found a nice little guide
[here](http://asm.sourceforge.net/intro/hello.html) for a simple Hello World in
assembly that summarises how to use `write()`. The first two things that matter
are that `eax` is set to 4, to indicate we want the syscall to be a write
operation (list of other syscalls
[here](http://asm.sourceforge.net/syscall.html)), and `ebx`
is set to 1, to specify that we want to write to `stdout`. Handily. a quick look
at the registers confirms that these are already set - saving us vital
instructions.

```
[0xf7750000]> dr eax
0x00000004
[0xf7750000]> dr ebx
0x00000001
```

For the actual writing of the message, we need to place a reference to the
location of the message in `ecx` and the length of the message in `edx`. We
don’t know how long the flag is going to be. So to save time and length, we’ll
just shove a big number in there (say, `edi`). This’ll cause
a bunch of garbage to be spat out after the flag, but we’ll definitely be
printing something out at the right length.

In summary, our code needs to look something like this:

```
mov ecx,edi ; Move the message to edi
mov edx,edi ; Set edx to something BIG
int 0x80    ; Call a system interrupt
```

Looks pretty legit. Let’s throw it in to rasm2 to get our resulting machine
code.

```
-> % rasm2 'mov ecx,edi; mov edx,edi; int 0x80'
89f989facd80
```

Fantastic. All our work so far has been compressed in to a lean 6 bytes. Now to
throw it at the binary and hope we get something useful.

```
-> % WUNTEE_CHALLENGE_FLAG=testing ./6yte 89f989facd80 
Shellcode location: 0xf7720000                        
Flag location: 0xffee6c60
flag-pwn3d
ÿÿÿÿo÷T÷X(r÷o÷¤mîÿ½r÷Ét÷°lîÿDmîÿo
<-- TONS OF STUFF REDACTED -->
```

I cut the output after a few nonsense bytes, but it carried on printing a fair
amount of nonsense until the program finally segfaulted. No matter, we’ve
managed to print our placeholder flag! Success! The only thing that remains is
to throw it in to the web interface I mentioned at the start and claim our flag.

Thanks for playing!
