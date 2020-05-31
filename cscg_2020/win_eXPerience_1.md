# win_eXPerience 1

For this challenge we are provided with a memory dump `memory.dmp` from a Windows XP machine.

Examining the memory dump in `volatility`, we see that a TrueCrypt volume was mounted:

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
0x816d8438 TrueCrypt.exe           200   1524      1       44      0      0 2020-03-22 18:28:02 UTC+0000
[...]

$ volatility truecryptsummary

Volatility Foundation Volatility Framework 2.6.1
[...]
File Object          \Device\TrueCryptVolumeE\password.txt at 0x1717be8
[...]
File Object          \Device\TrueCryptVolumeE\flag.zip at 0x1a3c7e8
[...]
```

Two files, `password.txt` and `flag.zip` are cached in memory. Let's extract them:

```sh
$ volatility dumpfiles -D . -n -Q 0x1717be8,0x1a3c7e8

Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x01717be8   None   \Device\TrueCryptVolumeE\password.txt
DataSectionObject 0x01a3c7e8   None   \Device\TrueCryptVolumeE\flag.zip

$ cat file.None.0x81a8ffa0.password.txt.dat

BorlandDelphiIsReallyCool

$ 7z e -p"BorlandDelphiIsReallyCool" file.None.0x81732ef8.flag.zip.dat

Extracting archive: file.None.0x81732ef8.flag.zip.dat
Everything is Ok

$ cat flag.txt

CSCG{c4ch3d_p455w0rd_fr0m_0p3n_tru3_cryp1_c0nt41n3r5}
```
