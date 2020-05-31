# reme Part 1

For this challenge we are provided with a .NET DLL `ReMe.dll`. Using `dnSpy`, we can easily decompile and even modify the contained code.

When the binary is started, it performs a couple of checks. One of those verifies that the password we supply as the first command line argument is correct. With `dnSpy`, we change the code to print the required password instead of `Nope` when an incorrect password in entered:

```diff
@@ -37,10 +37,11 @@
     Console.WriteLine("Usage: ReMe.exe [password] [flag]");
     Environment.Exit(-1);
 }
-bool flag5 = args[0] != StringEncryption.Decrypt("D/T9XRgUcKDjgXEldEzeEsVjIcqUTl7047pPaw7DZ9I=");
+string pass = StringEncryption.Decrypt("D/T9XRgUcKDjgXEldEzeEsVjIcqUTl7047pPaw7DZ9I=");
+bool flag5 = args[0] != pass;
 if (flag5)
 {
-    Console.WriteLine("Nope");
+    Console.WriteLine(pass);
     Environment.Exit(-1);
 }
 else
```

This prints the first flag: `CSCG{CanIHazFlag?}`
