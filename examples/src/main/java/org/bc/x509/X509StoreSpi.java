package org.bc.x509;

import java.util.Collection;
import org.bc.util.Selector;

public abstract class X509StoreSpi {
   public abstract void engineInit(X509StoreParameters var1);

   public abstract Collection engineGetMatches(Selector var1);
}
