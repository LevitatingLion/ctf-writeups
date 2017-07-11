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
