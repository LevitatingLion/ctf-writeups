# eVMoji

For this challenge we are provided with an ELF binary `eVMoji` and a file `code.bin`, which contains what appears to be code for a custom VM language made up entirely of UTF-8 encoded Emojis.

By statically reversing the ELF binary, we can confirm that suspicion: the code file is divided into 0x200 bytes of data, followed by UTF-8 encoded code points, which are interpreted as code by the VM. Apart from code and data, the VM provides a stack, which most instructions interact with.

## Instruction Set

The instruction set of the VM comprises 12 instructions, with the following code points and effects:

```
U+1F480 (skull):
    exit

U+2795 (heavy plus sign):
    top &= 1

U+27A1 (black rightwards arrow):
    skip
    top >>= arg

U+203C (double exclamation mark):
    skip
    push top

U+2705 (white heavy check mark):
    push pop | pop

U+270F (pencil):
    print len=pop string=&data[pop]
    skip

U+1F4D6 (open book):
    read len=pop string=&data[pop]

U+1F4AA (flexed biceps):
    push arg

U+1F9BE (mechanical arm):
    push *(i8 *)&data[arg]

U+1F320 (shooting star):
    push *(i32 *)&data[arg]

U+1F500 (shuffle):
    push pop ^ pop

U+1F914 (thinking face):
    if pop == pop: pc += arg
```

In the description of the instructions I used the following abbreviations:

```
exit: exit the program
top: top of the stack
push: push value to stack
pop: pop value from stack
skip: skip one codepoint
char: (get codepoint) - '0'; skip; skip
arg: pow(char, char) + pow(char, char) + pow(char, char)
```

## Code

Once we know the instruction set and encoding of the instructions, we can disassemble the VM code (huge parts omitted for readability):

```
0x0:        push 0x90
0x2e:       push 0x17
0x5c:       print len=pop string=&data[pop]
0x62:       push 0xa7
0x90:       push 0x14
0xbe:       print len=pop string=&data[pop]
0xc4:       push 0x0
0xf2:       push 0x1b
0x120:      read len=pop string=&data[pop]

0x124:      push 0x0
0x152:      push 0xf2
0x180:      push *(i8 *)&data[0x0]
0x1ae:      push pop ^ pop
0x1b2:      push 0x9c
0x1e0:      push pop ^ pop
0x1e4:      push pop | pop
[...]
0xe20:      push 0xa2
0xe4e:      push *(i8 *)&data[0x16]
0xe7c:      push pop ^ pop
0xe80:      push 0xfd
0xeae:      push pop ^ pop
0xeb2:      push pop | pop
0xeb5:      push 0x0
0xee3:      if pop == pop: jmp 0xf77
0xf11:      push 0xbb
0xf3f:      push 0x19
0xf6d:      print len=pop string=&data[pop]
0xf73:      exit

0xf77:      push *(i32 *)&data[0x8c]
0xfa5:      push top
0xfab:      top &= 1
0xfae:      push *(i32 *)&data[0x17]
0xfdc:      top >>= 0x0
0x100c:     top &= 1
0x100f:     if pop == pop: jmp 0x1129
0x103d:     top >>= 0x1
0x106d:     push *(i32 *)&data[0x80]
0x109b:     push pop ^ pop
0x109f:     push 0x0
0x10cd:     push 0x0
0x10fb:     if pop == pop: jmp 0x1159
0x1129:     top >>= 0x1
[...]
0x4471:     push top
0x4477:     top &= 1
0x447a:     push *(i32 *)&data[0x17]
0x44a8:     top >>= 0x1f
0x44d8:     top &= 1
0x44db:     if pop == pop: jmp 0x45f5
0x4509:     top >>= 0x1
0x4539:     push *(i32 *)&data[0x80]
0x4567:     push pop ^ pop
0x456b:     push 0x0
0x4599:     push 0x0
0x45c7:     if pop == pop: jmp 0x4625
0x45f5:     top >>= 0x1
0x4625:     push *(i32 *)&data[0x88]
0x4653:     push pop ^ pop
0x4657:     push 0x0
0x4685:     if pop == pop: jmp 0x4719
0x46b3:     push 0xd4
0x46e1:     push 0x17
0x470f:     print len=pop string=&data[pop]
0x4715:     exit

0x4719:     push 0xeb
0x4747:     push 0x15
0x4775:     print len=pop string=&data[pop]
0x477b:     push 0x0
0x47a9:     push 0x1b
0x47d7:     print len=pop string=&data[pop]
0x47dd:     push 0x100
0x480b:     push 0x2
0x4839:     print len=pop string=&data[pop]
0x483f:     exit
```

That's a lot of code, but thankfully we can see a lot of repeating patterns. Using the patterns we can split the code in four parts.

### First Part

The first part (offsets 0x0 to 0x124) prints two strings asking for the flag and then reads 0x1b bytes of our input into the data space at offset 0x0.

### Fourth Part

The fourth part (offsets 0x4719 to the end) prints the message `Thats the flag: CSCG{$input}`, where `$input` is our input from the first part. So, we obtain the flag by finding an input which passes all the checks from the second and third part.

### Second Part

The second part (offsets 0x124 to 0xf77) is where it gets more interesting: we see `push 0x0` followed by repeating patterns of the form

```
push $const_a
push *(i8 *)&data[$index]
push pop ^ pop
push $const_b
push pop ^ pop
push pop | pop
```

where `$const_a`, `$const_b` are hardcoded values and `$index` goes from `0x0` to `0x16`. This pattern XORs `$const_a`, `$const_b` and the byte at `$index` in our input together, and ORs the result to the top of the stack. The part ends with:

```
push 0x0
if pop == pop: jmp part_three
push 0xbb
push 0x19
print len=pop string=&data[pop]
exit
```

Here, if the top of the stack is zero, it jumps to part three of the code. If the top of the stack is not zero, a message is printed and the program terminates.

Since we don't want the program to terminate early, we determine the input that leads to the third part by XORing all `$const_a`s with all `$const_b`s:

```python
>>> xor([0xf2, 0xea, 0x82, 0x36, 0x8e, 0x12, 0x18, 0x73, 0x7b, 0x11, 0x5b, 0x69, 0x38, 0x8a, 0xb0, 0x8b, 0x8e, 0x83, 0xf6, 0xc4, 0x39, 0xf5, 0xa2], [0x9c, 0xd9, 0xf5, 0x69, 0xef, 0x75, 0x2b, 0x2c, 0xd, 0x20, 0x29, 0x1d, 0x4d, 0xbe, 0xdc, 0xe2, 0xf4, 0xb7, 0x82, 0xf5, 0x56, 0x9b, 0xfd])
b'n3w_ag3_v1rtu4liz4t1on_'
```

There's the first segment of the flag!

### Third Part

The third part (offsets 0xf77 to 0x4719) consists of a `push *(i32 *)&data[0x8c]` followed by once again repeating patterns, this time of the form

```
        push top
        top &= 1
        push *(i32 *)&data[0x17]
        top >>= $shift_amount
        top &= 1
        if pop == pop: jmp end
        top >>= 0x1
        push *(i32 *)&data[0x80]
        push pop ^ pop
        push 0x0
        push 0x0
        if pop == pop: jmp next
end:    top >>= 0x1
next:
```

where `$shift_amount` goes from `0x0` to `0x1f`. The part ends with:

```
push *(i32 *)&data[0x88]
push pop ^ pop
push 0x0
if pop == pop: jmp part_four
push 0xd4
push 0x17
print len=pop string=&data[pop]
exit
```

All of this can be translated into the following pseudocode:

```python
# data @ 0x80
xor = 0xedb88320
# data @ 0x8c
top = 0xffffffff

for i in range(0x20):
    if top & 1 == (input >> i) & 1:
        top >>= 1
    else:
        top >>= 1
        top ^= xor

# data @ 0x88
assert top == 0xf40e845e
```

We know that the highest bit of `top` must be set, so the XOR in the last loop operation must happen, i.e. the branch condition must be false. Working backwards from that, we can deduce the penultimate branch condition, and so on. Solving iteratively:

```python
xor = 0xedb88320
top = 0xf40e845e

ifs = []
for i in range(0x20):
    if top & 0x80000000:
        ifs = [False] + ifs
        top ^= xor
    else:
        ifs = [True] + ifs
    top <<= 1

print(ifs)
```

Now we know which results the comparisons should produce. To get the flag, we do a final forward pass over the loop:

```python
xor = 0xedb88320
top = 0xffffffff

flag = 0
for i in range(0x20):
    flag |= ((top & 1) ^ ifs[i] ^ 1) << i
    if ifs[i]:
        top >>= 1
    else:
        top >>= 1
        top ^= xor

print(p32(flag))
```

Append that to the first part of the flag to finally get:

Flag: `CSCG{n3w_ag3_v1rtu4liz4t1on_l0l?}`
