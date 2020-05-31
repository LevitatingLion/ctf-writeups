# reme Part 2

For this challenge we are provided with a .NET DLL `ReMe.dll`. Using `dnSpy`, we can easily decompile and even modify the contained code.

When the binary is started, it performs a couple of checks and then decrypts and loads a second, nested DLL. With `dnSpy`, we patch the `Main` function to dump the DLL to a file instead of loading it. After exporting the patched DLL, we have to manually append the encrypted data after 'THIS_IS_CSCG_NOT_A_MALWARE' from the original file, because `dnSpy` doesn't include it.

Analyzing the dumped DLL, our input is checked by the following function:

```csharp
public static void Check(string[] args)
{
    bool flag = args.Length <= 1;
    if (flag)
    {
        Console.WriteLine("Nope.");
    }
    else
    {
        string[] array = args[1].Split(new string[]
        {
            "_"
        }, StringSplitOptions.RemoveEmptyEntries);
        bool flag2 = array.Length != 8;
        if (flag2)
        {
            Console.WriteLine("Nope.");
        }
        else
        {
            bool flag3 = "CSCG{" + array[0] == "CSCG{n0w" && array[1] == "u" && array[2] == "know" && array[3] == "st4t1c" && array[4] == "and" && Inner.CalculateMD5Hash(array[5]).ToLower() == "b72f3bd391ba731a35708bfd8cd8a68f" && array[6] == "dotNet" && array[7] + "}" == "R3333}";
            if (flag3)
            {
                Console.WriteLine("Good job :)");
            }
        }
    }
}
```

Googling for the md5 hash `b72f3bd391ba731a35708bfd8cd8a68f`, we find it's the hash of `dynamic`. With that, the second flag is `CSCG{n0w_u_know_st4t1c_and_dynamic_dotNet_R3333}`.
