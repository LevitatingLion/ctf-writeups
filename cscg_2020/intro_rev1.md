# Intro to Reversing 1

For this challenge we are provided with an ELF binary `rev1`. When run, the binary asks us for a password. Let's run it with `ltrace` to see if it calls any interesting library functions:

```sh
$ ltrace ./rev1
fopen("./flag", "r")                                  = 0x55902fb25eb0
fread(0x55902ddc7040, 256, 1, 0x55902fb25eb0)         = 0
fclose(0x55902fb25eb0)                                = 0
puts("Give me your password: "Give me your password:
)                       = 24
read(0asdf
, "asdf\n", 31)                                 = 5
strcmp("asdf", "y0u_5h3ll_p455")                      = -24
puts("Thats not the password!"Thats not the password!
)                       = 24
+++ exited (status 0) +++
```

The binary compares our input with `y0u_5h3ll_p455`, so that's probably the correct password. We get the flag by entering that password on the server:

```sh
$ nc hax1.allesctf.net 9600
Give me your password:
y0u_5h3ll_p455
Thats the right password!
Flag: CSCG{ez_pz_reversing_squ33zy}
```
