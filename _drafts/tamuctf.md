---
layout: post
title: "TamuCTF writeups pt. 1"
categories: blog writeups re tamu
---

I enjoyed doing the first CTF write-up so I thought I'd try my hand at another.
This CTF involved quite a wide array of different types of tests - I especially
enjoyed the secure coding/config ones, which isn't something I've experienced
in a CTF before.

Rather than just one challenge. I'm going to document all the challenges I
solved, or took part in solving. Therefore I'm gonna split it up in to several
parts, else these posts will be just too long.

[TamuCTF](https://ctf.tamu.edu/) is another beginner CTF, hosted by Texas A&M.
Since I'm still basically a beginner, this seemed perfect.

## The challenges

### Band-aid (reversing)

I'll admit, this one took me far too long to solve. When you see why, you'll
laugh. I did. It was that or cry.

> Sometimes all you need is a little change in life.

The user is given the [binary]({{"assets/e0dd79b3d9b05e80" | absolute_url}}),
the above clue, and that's it. Let's run that binary.

```
-> % ./e0dd79b3d9b05e80
 this code needs a band aid
```

Just prints a message and quits. Oh well, let's take a look at it in `r2`
instead. The first thing I always do is `aaa; pdf @ sym.main`, which anaylses
the binary and prints the dissasembly of `main()`. Towards the end of `main()`
are the following instructions:

```
    0x08048ced      817df44b1200.  cmp dword [local_ch], 0x124b ; [0x124b:4]=-1
,=< 0x08048cf4      7e0c           jle 0x8048d02
|   0x08048cf6      e8f0fdffff     call sym.f2
|   0x08048cfb      b800000000     mov eax, 0
==< 0x08048d00      eb05           jmp 0x8048d07

```
A reference to another function. Let's run it. We're going to set a breakpoint
on the `jle` just before the call, change the instruction pointer to the call
and continue execution.

```
[0xf7eecc70]> db 0x08048cf4; dc; dr eip=0x08048cf6; dc
 this code needs a band aid
hit breakpoint at: 8048cf4
result 
L/R8ejlvVP4+JvgvsSI+JaLn6YCArf5fTAIfUwMNCrJ8HkRkQLEB5RH5COF1+9mSQoGY8wG23AtDyM0OEgm+zFCTibFOgieixjrv5OHAIB+akOahMWoyt/qAGnK9ZsLsv20apyzlH0llafbfQ0MkurU/c8O3Xj3m0VL1GOjHk14=
LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlDV3dJQkFBS0JnUUNjVDRaalluR2lNWXRFZDcrL1l0RmdHRTNlZ1RrV0Jpd2hXQ240MUxQU1lzdXErNE9RCnBuQk1ZUjVZdExiOTRXTzdpNnZHYU9PTnNzSE5kWUFkblJETThpTFN2L3JUMHVPdGdTd2RaTmlMQzduNmdILzgKOFJqRlFFTGptSldRemdzWDhDVXFkWm80SnJNZkJTbXd3RFlBNUJtMGI3Nmd6bXFoK3lMWGErdW5PUUlEQVFBQgpBb0dBYWNhUy9adzNvM2Q5Yy9iSkpqMDd6SmlGMFdXRytQVnlWWm93eFBkRFBNS29hbXRMYTg2RnZkb1d6QloyCm9yVXNaVlN1Q0ZVZ2I5b2d0ZVdtcmVPRTR1d0FQK0RGKzJpU1h0MlZxTEdJZ29ieDZib0YrTktjMXNvUUFEaFQKNkw2emZNSzFNVzZwSDVYUGNVNUg4QU1TWUREYVFxeEVtWEp0azg4OUxJTVpVUUVDUVFDNDRYVjRqdEwwcjFkcQpjY1ByTlIrTEp4UjExMkJPMEhXLzduRVEwQUtUbUhIZ2EvbmV1ejMycHF1TVNRM2xodXRTNW5kanNzdmJ3dHJuCjNWdVhKRUJaQWtFQTJIQ1E0bE12MHI5Y3B2b2lCTVR0cDlYS2dIeU5Vbmd3dE1SODZ6VE0vK1dudlhTWjlDZk8KWXhyMlVvd2daMTlPNXpCZDFrVGRZQnNMbFVoL2syekI0UUpBWWtMeVBIRXNqZi9qWmgreEVZSGFrZ3JqUlA2RApvV0FLTlVoMXI0bmUxTE5oVXZZUWgrRGN2Z3MzZ2dnUjZyd2F0cVRuTDRZSDgzVk5BNDhTN3ZIRmdRSkFkeFZvCkFiNDNQOExkM1ZrZVFuVi9OS3FpSWhObFJneXU3Nlp6L0kwdWhWVDc5M2NpQlgycFJrbmRZUW1NQXBRanUzdVgKQlg4YU5maHJaUlZnYStLWXdRSkFYY1RKemE3ODNFeVk1YmxTZWIvWlJGYzZjdnFERDlRSDRXRVQ1b000ZjFnWgprZlI3Ti9qcEc4b09sZkl5d2o1RStaaHJaSTlEY1RmQjVnQWlFRHFrQmc9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQ==
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDY1Q0WmpZbkdpTVl0RWQ3Ky9ZdEZnR0UzZQpnVGtXQml3aFdDbjQxTFBTWXN1cSs0T1FwbkJNWVI1WXRMYjk0V083aTZ2R2FPT05zc0hOZFlBZG5SRE04aUxTCnYvclQwdU90Z1N3ZFpOaUxDN242Z0gvODhSakZRRUxqbUpXUXpnc1g4Q1VxZFpvNEpyTWZCU213d0RZQTVCbTAKYjc2Z3ptcWgreUxYYSt1bk9RSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==
```

Ooh, chunks of base64. Decoding them, we get some interesting files. It looks
like the first chunk is random data. The 2nd is a PEM RSA private key, and the
final one is ASCII text (which is actually the public key).

```
-> % file one two three
one:   data
two:   PEM RSA private key
three: ASCII text
```

Ok, so if 'one' is data, it's safe to say it's some RSA-encrypted ciphertext.
Let's break out `openssl` to decrypt this nonsense.

```
-> % openssl rsautl -decrypt -in one -inkey two
RSA operation error
139640308404416:error:0407109F:rsa routines:RSA_padding_check_PKCS1_type_2:pkcs decoding error:../crypto/rsa/rsa_pk1.c:241:
139640308404416:error:04065072:rsa routines:rsa_ossl_private_decrypt:padding check failed:../crypto/rsa/rsa_ossl.c:487:
```

A padding error. That's odd. Maybe I missed something? This served as
a lesson to me that maybe you should read the man-page before instinctively
googling for an answer. The Stack Overflow answers I got all pointed to corrupt
ciphertext. Oh no, I thought, did I miss something? After studying the binary
a while longer, I decided to just double-check the syntax for rsautl.

```
-> % openssl rsautl --help                          
Usage: rsautl [options]
Valid options are:
....
 -raw                     Use no padding
...
```

Oh, how embarassing. Let's try that again with `-raw`.

```
-> % openssl rsautl -decrypt -in one -inkey two -raw
gigem{pirate_iter_v2_660c6b7aed3b905b}
```

Much better. To the next flag!

### nginx (Secure Coding)

> My friend set up a web server using nginx but he keeps complaining that people are finding files that they are not supposed to be able to get to. Can you fix his configuration file for him?

Ah, securing Nginx. This is our first secure-coding/configuration challenge
so I'll explain a little how it works. You are given access to a
[Gitlab](https://gitlab.com) repository containing the broken config. You are
supposed to fork the repo, edit the config and commit it to your fork. When you
do this, it triggers a CI run within Gitlab, where it runs some tests (the
contents of which we do not know). In the test output, if you are successful,
there will be the flag. I like this because it exposes users to a very real part
of software development - running your tests and watching with baited breath as
it either chastises you or congratulates you on not breaking everything.

I put a copy of the config [here]({{"assets/tamu/default" | absolute_url}}), but
I'll stick the relevant snippets below.

In Nginx, we configure in which directory to look for files with the `root`
directive. We can see that the poor user's got the following line:

```
root /;
```

Then, within the `location` block, they've got

```
index /usr/share/nginx/html/index.html;
```

This means that when they go to (for example) `mysite.com/index.html`, it's
sure enough going to navigate to `/usr/share/nginx/html/index.html`, but if they,
for example, try to navigate to `mysite.com/etc/passwd`, it's gonna happily show
them the contents of this file.

It's a simple two-line fix.

```
- root /;
+ root /usr/share/nginx/html/;

- index /usr/share/nginx/html/index.html;
+ index index.html;
```

Then we commit the changes, and watch the build output.

```
<trimmed for brevity>
Pushing: {'serviceHost': '172.17.0.3', 'userInfo': u'4c0f83e0d197b0c25d4c49a338a6f9807cb478c14d9c30f8c982c4a1f428c55e', 'chal': 'nginx'}
Service Check Succeeded After Attack
flag: gigem{f1x1N_conF1g5_0533cfc}
Job succeeded
```

Nice.

### sql (Secure Coding)

> I created a login form for my web page. Somehow people are logging in as admin without my password though!
Can you fix my login code for me?

As soon as I saw the name of the challenge, and the `.php` extension, I just knew
this was gonna be injection. Taking a look at the source of `login.php`, which
I've hosted [here]({{"assets/tamu/login.php" | absolute_url}}), I immediately
see what the problem is.

```
$sql = "SELECT * FROM Users WHERE User='$user' AND Password='$pass' ORDER BY ID";
```

This line is a classic vector for SQL injection. By letting `$user` contain bits
of SQL, we can cause this statement to do whatever we want. For instance, if a
malicious user were to set $user to 'admin' and $password to something like
`blahblahblah' or 1=1--`, they would be able to force themselves in as an admin.

There are several ways around this, such as manually attempting to escape
the user input. But for me, the best way is with [prepared statements](https://www.w3schools.com/php/php_mysql_prepared_statements.asp).

Prepared statements handle the escaping, etc of provided input and don't allow
for the injection of SQL commands in queries. Below is the snippet I used,
replacing the above SQL statement and the `if ($result = $con->query($sql)` line.

```
    $stmt = $conn->prepare("SELECT * FROM Users where User=? AND Password=? ORDER BY ID");
    $stmt->bind_param("ss",$user,$pass);
    $stmt->execute();

    if ($result = $stmt->get_result()) // Query
```

We prepare a statement, bind the parameters to that statement, execute the
statement and reap the results.

```
Pushing: {'serviceHost': '172.17.0.3', 'userInfo': u'382ac7122e105b260534f9ec99602ac43c6fa8ab607f706244630df179a3a863', 'chal': 'SQL'}
Service Check Succeeded After Attack
flag: gigem{cAn_y0U_sQL_TH3_Pr0bL3m?_9f431b}
```

Nice.

### shell-plugin (Secure coding)

> I'm running a CTF competition that is geared towards newer students. I know that most of the students don't have easy access to a linux machine so why not give students shell access to my server so that they can use it to solve challenges?
In order to make this a reality I wrote this cool plugin for CTFd to automatically create an account when they register for the competition.
One of the students claims that they can get a root shell on my server though. Can you figure out what happened and fix the issue for me?

Our first look at this repository reveals three files of interest - the Python
script `script_server.py`[[1]]({{"assets/tamu/script_server.py" | absolute_url}}),
and two scripts; `add-user.sh`[[2]]({{"assets/tamu/add-user.sh" | absolute_url}})
and `change-user-pass.sh`[[3]]({{"assets/tamu/change-user-pass.sh" | absolute_url}})
Taking a look at the first file, it seems like it just provides arguments to
the shell script. The shell-scripts run some standard UNIX commands to add and modify
users. I decide to pay more attention to the Python script, since I know from
experience how easy it is to accidentally cause command injection vectors with
flippant `system()` calls.

It looks like if I send certain usernames to this script, I can get away with
command execution. What's more, we know they must run as root since that's the
only user that can change user passwords (or some user in `/etc/sudoers` that
can run this script with root privileges, which amounts to the same).

Let's try by creating a pretend `add_user_func()` which instead just prints the
command it would run:

```
def add_user_func(name, password):
   print("./add-user.sh " + name + " " + password)
```

We can see from this that it's absolutely trivial to inject nefarious shell
commands in to this script:

```
>>> add_user_func("hello","world")
./add-user.sh hello world
>>> add_user_func("hello","world; some command as root here")
./add-user.sh hello world; some command as root here
```

There are many options; opening a reverse TCP shell, changing root's password
and hoping they've got root login enabled, etc. Basically, it's a huge security
flaw. I'm thinking the solution needs to be either escaping characters in the
arguments provided to `add_user_func` or, even simpler, just surround them with
apostrophes so they aren't interpreted as shell commands. Here's what my changes
look like:

```
- os.system("./add-user.sh " + name + " " + password)
+ name = name.translate(None, "'")
+ password = password.translate(None, "'")
+ os.system("./add-user.sh '" + name + "' '" + password + "'")

- os.system("./change-user-pass.sh " + name + " " + password)
+ name = name.translate(None, "'")
+ password = password.translate(None, "'")
+ os.system("./change-user-pass.sh '" + name + "' '" + password + "'")
```

Before passing the arguments, I replace any apostrophe with nothing, then in the
call to `os.system`, surround the argument with apostrophes. This does a good
job of making sure the user cannot inject any additional commands in to the
script.

Let's see how we did.

```

127.0.0.1 - - [18/Feb/2018 19:37:33] "POST /RPC2 HTTP/1.1" 200 -
172.17.0.1 - - [18/Feb/2018 19:37:33] "POST /register HTTP/1.1" 302 -
172.17.0.1 - - [18/Feb/2018 19:37:33] "GET /challenges HTTP/1.1" 200 -
172.17.0.1 - - [18/Feb/2018 19:37:33] "GET /register HTTP/1.1" 200 -
Enter new UNIX password: Retype new UNIX password: passwd: password updated successfully
127.0.0.1 - - [18/Feb/2018 19:37:33] "POST /RPC2 HTTP/1.1" 200 -
172.17.0.1 - - [18/Feb/2018 19:37:33] "POST /register HTTP/1.1" 302 -
172.17.0.1 - - [18/Feb/2018 19:37:33] "GET /challenges HTTP/1.1" 200 -
172.17.0.3
Pushing: {'serviceName': '676b5f65de36fb2f09720e52fd6e4413ab089d9e8fbd781ec0768ec74ebf601c', 'serviceHost': '172.17.0.3', 'userInfo': u'5315473e104dc93edcce819e46eda994ce575c8ef6dbd860099af59b0ecf17b8', 'chal': 'shell'}
Service Check Succeeded After Attack
flag: gigem{gH0s7_in_7h3_Sh3ll_fb63a0}
```

Nice!
