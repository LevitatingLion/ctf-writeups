# Intro to Reversing 3

For this challenge we are provided with an ELF binary `rev3`. When run, the binary asks us for a password. Let's run it with `ltrace` to see if it calls any interesting library functions:

```sh
$ ltrace ./rev3
fopen("./flag", "r")                                  = 0x55ebe0412eb0
fread(0x55ebdf7cd040, 256, 1, 0x55ebe0412eb0)         = 0
fclose(0x55ebe0412eb0)                                = 0
puts("Give me your password: "Give me your password: 
)                       = 24
read(0AAAAAAAA
, "AAAAAAAA\n", 31)                             = 9
strcmp("IHKJMLON", "lp`7a<qLw\036kHopt(f-f*,o}V\017\025J") = -35
puts("Thats not the password!"Thats not the password!
)                       = 24
+++ exited (status 0) +++
```

Apparently the binary transforms our input in some way and then compares it to a hardcoded string. When playing around with the transformation, we notice that every character in our input only affects characters in the output at the same or a later position:

- `AAAAAAAA` -> `IHKJMLON`

- `AAAAAAAB` -> `IHKJMLOQ`

- `AAAAABAA` -> `IHKJMKON`

Because of that, we can bruteforce the correct password character by character. The following shell script performs this bruteforce, retrieving the transformation of each input from the output of `ltrace`:

```sh
#!/bin/bash

flag=
while true; do
    # loop over all printable ascii characters
    for i in {40..126}; do
        # convert the number to a character and append it to the current flag prefix
        try="${flag}$(printf "\\x$(printf "%x" "$i")")"
        # run the binary and extract the transformation of the input
        res="$(<<< "$try" ltrace ./rev3 |& grep -Eo '^strcmp\(".*", "' | cut -c9- | rev | cut -c5- | rev)"
        # print status
        printf "try: %q, res: %q\n" "$try" "$res"
        # if the transformation matches the beginning of the fixed string, we found the next char
        if [[ 'lp`7a<qLw\036kHopt(f-f*,o}V\017\025J' =~ ^"$res" ]]; then
            flag="$try"
            break
        fi
    done
done
```

This gives us the password `dyn4m1c_k3y_gen3r4t10n_y34h`. Entering it on the server yields the flag `CSCG{pass_1_g3ts_a_x0r_p4ss_2_g3ts_a_x0r_EVERYBODY_GETS_A_X0R}`.
