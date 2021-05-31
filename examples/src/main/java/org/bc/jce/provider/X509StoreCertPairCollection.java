package org.bc.jce.provider;

import java.util.Collection;
import org.bc.util.CollectionStore;
import org.bc.util.Selector;
import org.bc.x509.X509CollectionStoreParameters;
import org.bc.x509.X509StoreParameters;
import org.bc.x509.X509StoreSpi;

public class X509StoreCertPairCollection extends X509StoreSpi {
   private CollectionStore _store;

   public void engineInit(X509StoreParameters var1) {
      if (!(var1 instanceof X509CollectionStoreParameters)) {
         throw new IllegalArgumentException("Initialization parameters must be an instance of " + X509CollectionStoreParameters.class.getName() + ".");
      } else {
         this._store = new CollectionStore(((X509CollectionStoreParameters)var1).getCollection());
      }
   }

   public Collection engineGetMatches(Selector var1) {
      return this._store.getMatches(var1);
   }
}
