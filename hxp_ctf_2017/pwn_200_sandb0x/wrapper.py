#!/usr/bin/env python3

import os
from subprocess import check_output, call, DEVNULL, STDOUT
from tempfile import TemporaryDirectory

def sanitize(code):
    code = code.replace(".global", "")
    if "." in code:
        print("You're waay too bad!")
        exit(1)

WHITELIST = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ%.,;:()$_- "
code = input("x86-64> ")
code = "".join(c for c in code if c in WHITELIST)[:80]
sanitize(code)

code = ".global function;function:" + code + ";ret\n"

with TemporaryDirectory() as tmp:
    with open(tmp + "/user.s", "w") as f:
        f.write(code)
    try:
        out = check_output(["gcc", "-o", tmp + "/user", "main.c", tmp + "/user.s", "-lseccomp"], stdin=DEVNULL)
    except Exception as e:
        print("Compile error:\n", e)
        exit(1)
    call(tmp + "/user")
