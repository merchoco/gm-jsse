package org.bc.util;

import java.util.Collection;

public interface Store {
   Collection getMatches(Selector var1) throws StoreException;
}
