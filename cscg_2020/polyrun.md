# Polyrun

For this challenge we are provided with a Perl script `run.pl`. Running `binwalk` on the file reveals "Windows Script Encoded Data" at offset 0x96, in the string `#@~^UgAAAA==v,Zj;MPKtb/|r/|Y4+|0sCT{XKN@#@&H/T$G6,J;?/M,P_qj{g6K|I3)d{sJ)VTE~,#~rF}x^X~,JgGwJexkAAA==^#~@`.

Decoding this using [CyberChef](https://gchq.github.io/CyberChef/#recipe=Microsoft_Script_Decoder()&input=I0B%2BXlVnQUFBQT09dixaajtNUEt0Yi98ci98WTQrfDBzQ1R7WEtOQCNAJkgvVCRHNixKOz8vTSxQX3Fqe2c2S3xJMylke3NKKVZURX4sI35yRn14Xlh%2BLEpnR3d/SmV4a0FBQT09XiN%2BQA) yields the flag: `CSCG{This_is_the_flag_yo}`
