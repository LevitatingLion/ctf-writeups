# Intro to Reversing 2

For this challenge we are provided with an ELF binary `rev2`. When run, the binary asks us for a password. Let's run it with `ltrace` to see if it calls any interesting library functions:

```sh
$ ltrace ./rev2
fopen("./flag", "r")                                  = 0x557172dd4eb0
fread(0x557171f74040, 256, 1, 0x557172dd4eb0)         = 0
fclose(0x557172dd4eb0)                                = 0
puts("Give me your password: "Give me your password:
)                       = 24
read(0AAAAAAAA
, "AAAAAAAA\n", 31)                             = 9
strcmp("\312\312\312\312\312\312\312\312", "\374\375\352\300\272\354\350\375\373\275\367\276\357\271\373\366\275\300\272\271\367\350\362\375\350\362\374") = -50
puts("Thats not the password!"Thats not the password!
)                       = 24
+++ exited (status 0) +++
```

Apparently the binary transforms our input in some way and then compares it to a hardcoded string. When we enter `B`s or `C`s instead of `A`s, we see the following output:

```sh
$ ltrace ./rev2
fopen("./flag", "r")                                  = 0x5566103dfeb0
fread(0x55660eef9040, 256, 1, 0x5566103dfeb0)         = 0
fclose(0x5566103dfeb0)                                = 0
puts("Give me your password: "Give me your password:
)                       = 24
read(0BBBBBBBB
, "BBBBBBBB\n", 31)                             = 9
strcmp("\313\313\313\313\313\313\313\313", "\374\375\352\300\272\354\350\375\373\275\367\276\357\271\373\366\275\300\272\271\367\350\362\375\350\362\374") = -49
puts("Thats not the password!"Thats not the password!
)                       = 24
+++ exited (status 0) +++
$ ltrace ./rev2
fopen("./flag", "r")                                  = 0x55fe29816eb0
fread(0x55fe2816f040, 256, 1, 0x55fe29816eb0)         = 0
fclose(0x55fe29816eb0)                                = 0
puts("Give me your password: "Give me your password:
)                       = 24
read(0CCCCCCCC
, "CCCCCCCC\n", 31)                             = 9
strcmp("\314\314\314\314\314\314\314\314", "\374\375\352\300\272\354\350\375\373\275\367\276\357\271\373\366\275\300\272\271\367\350\362\375\350\362\374") = -48
puts("Thats not the password!"Thats not the password!
)                       = 24
+++ exited (status 0) +++
```

`A` is transformed to `\xca`, `B` to `\xcb` and `C` to `\xcc`, that looks like addition of `0x89`. When subtracting `0x89` from each character in the hardcoded string, we get the password `sta71c_tr4n5f0rm4710n_it_is`. Enter that on the server to get the flag: `CSCG{1s_th4t_wh4t_they_c4ll_on3way_transf0rmati0n?}`.
