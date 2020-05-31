# win_eXPerience 2

For this challenge we are provided with a memory dump `memory.dmp` from a Windows XP machine.

Examining the memory dump in `volatility`, we see that an executable `CSCG_Delphi.exe` is running:

```sh
$ export VOLATILITY_LOCATION=file://$PWD/memory.dmp
$ volatility imageinfo

Volatility Foundation Volatility Framework 2.6.1
[...]
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : VirtualBoxCoreDumpElf64 (Unnamed AS)
                     AS Layer3 : FileAddressSpace (./memory.dmp)
[...]
     Image Type (Service Pack) : 2
[...]

$ export VOLATILITY_PROFILE=WinXPSP2x86
$ volatility pslist

Volatility Foundation Volatility Framework 2.6.1
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
[...]
0x8173ec08 CSCG_Delphi.exe        1920   1524      1       29      0      0 2020-03-22 18:27:45 UTC+0000
[...]
```

Let's dump the executable to further analyze it:

```sh
$ volatility filescan | grep Delphi

Volatility Foundation Volatility Framework 2.6.1
0x0000000001a0c988      1      0 R--rwd \Device\HarddiskVolume1\Documents and Settings\CSCG\Desktop\CSCG\CSCG_Delphi.exe
0x0000000001a7a3a0      1      0 R--rwd \Device\HarddiskVolume1\Documents and Settings\All Users\Start Menu\Programs\Borland Delphi 7\Delphi 7.lnk
0x0000000001aaa6b0      1      0 R--rwd \Device\HarddiskVolume1\Documents and Settings\CSCG\Desktop\CSCG\CSCG_Delphi.exe

$ volatility dumpfiles -D . -n -Q 0x0000000001aaa6b0

Volatility Foundation Volatility Framework 2.6.1
ImageSectionObject 0x01aaa6b0   None   \Device\HarddiskVolume1\Documents and Settings\CSCG\Desktop\CSCG\CSCG_Delphi.exe
DataSectionObject 0x01aaa6b0   None   \Device\HarddiskVolume1\Documents and Settings\CSCG\Desktop\CSCG\CSCG_Delphi.exe
```

This leaves us with two new files, `file.None.0x81a90598.CSCG_Delphi.exe.dat` and `file.None.0x81ab6698.CSCG_Delphi.exe.img`. Both look like valid PE executables, but only `file.None.0x81ab6698.CSCG_Delphi.exe.img` actually runs, so it's probably close to the original executable.

Loading the executable in IDA, we see interesting string references pointing to the function `_TForm1_Button1Click`. Upon further inspection, we realize this function validates if our input is a valid flag. It checks that our input begins with `CSCG{` and ends with `}`. Afterwards our input is split into five parts separated by `_`. These parts are then reversed, hashed using MD5 and compared to hardcoded strings. We can find four of the five parts online when searching for the hash:

```
1efc99b6046a0f2c7e8c7ef9dc416323 dl0
c129bd7796f23b97df994576448caa23 l00hcs
017efbc5b1d3fb2d4be8a431fa6d6258
25db3350b38953836c36dfb359db4e27 kc4rc
40a00ca65772d7d102bb03c3a83b1f91 !3m
```

So far the flag is `CSCG{0ld_sch00l_XXX_cr4ck_m3!}`, where `XXX` is unknown. Since the challenge is written in Delphi, the missing part is likely some variation of `delphi`. Let's bruteforce that using a small shell script:

```sh
for x in {I,i,1}{H,h,5}{P,p}{L,l,1}{E,e,3}{D,d,5}; do
    printf "%s %s\n" "$(echo -n "$x" | md5sum)" "$x";
done | grep 017efbc5b1d3fb2d4be8a431fa6d6258

# output: 017efbc5b1d3fb2d4be8a431fa6d6258  - 1hp13d
```

Flag: `CSCG{0ld_sch00l_d31ph1_cr4ck_m3!}`
