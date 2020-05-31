# StayWoke Shop

For this challenge we are provided with the URL of a webshop `http://staywoke.hax1.allesctf.net/`.

Playing around with the shop, we notice a hidden `paymentEndpoint` parameter set to `http://payment-api:9090` on checkout; we can probably mess with the payment API by changing or appending to this URL. When specifying the account number `.`, we receive the error message `Cannot GET /wallets/balance\n\nTry GETting /help for possible endpoints.`. The account number `..` generates the error `Cannot GET /balance\n\nTry GETting /help for possible endpoints.`. From this we can deduce that the server probably requests `${paymentEndpoint}/wallets/${accountNumber}/balance`.

Slashes and other special characters seem to be filtered from the account number, but not from the payment endpoint, so we can issue arbitrary API commands by specifying a `paymentEndpoint` of e.g. `http://payment-api:9090/help?`, which returns `{"endpoints":[{"method":"GET","path":"/wallets/:id/balance","description":"check wallet balance"},{"method":"GET","path":"/wallets","description":"list all wallets"},{"method":"GET","path":"/help","description":"this help message"}]}`. Let's list all available wallets with `http://payment-api:9090/wallets?`: `[{"account":"1337-420-69-93dcbbcd","balance":133500}]`. Now we have access to an account with a balance of 1335€, great! But how do we get the flag?

Looking at all the products in the shop, we notice that their IDs start at `2` and increase from there, there's no product with ID `1`. Navigating to `http://staywoke.hax1.allesctf.net/products/1`, we can see that this hidden product is the flag! It costs 1337€ and we only have access to 1335€, but we can get around this limitation using the 20% discount code `I<3CORONA`: when we apply the code, a new "discount" item with a negative price is added to our cart, but when we then remove items from our cart the price of the special "discount" item remains the same.

Putting it all together, we can buy the flag by adding 10x tinfoil to our cart, applying the discount code, then removing all of the tinfoil, adding the flag, and supplying the leaked account number at checkout.

Flag: `CSCG{c00l_k1ds_st4y_@_/home/}`
