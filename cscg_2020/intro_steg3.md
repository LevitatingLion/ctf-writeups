# Intro to Stegano 3

For this challenge we are provided with an image `chall.png`.

Examining the image in `stegsolve`'s "random color map", we can see hidden text: "The password is: s33_m3_1f_y0u_c4n". Using `binwalk`, we can extract a hidden `zip` archive from the image and unpack it using the password:

```sh
$ binwalk -e chall.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 676 x 437, 8-bit/color RGBA, non-interlaced
99            0x63            Zlib compressed data, best compression
299068        0x4903C         Zip archive data, encrypted compressed size: 48, uncompressed size: 28, name: flag.txt
299266        0x49102         End of Zip archive, footer length: 22

$ 7z e -p"s33_m3_1f_y0u_c4n" _chall.png.extracted/4903C.zip

Extracting archive: _chall.png.extracted/4903C.zip
Everything is Ok

Size:       28
Compressed: 220

$ cat flag.txt

CSCG{H1dden_1n_pla1n_s1ght}
```
