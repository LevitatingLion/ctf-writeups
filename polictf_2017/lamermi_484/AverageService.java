package it.polictf.lamermi;

import java.util.*;
import java.rmi.*;

public interface AverageService extends Remote {

	Double average(List<Integer> param) throws RemoteException;
}
