package org.bc.jcajce.provider.asymmetric.ec;

import org.bc.crypto.DSA;
import org.bc.crypto.Digest;
import org.bc.jcajce.provider.asymmetric.util.DSAEncoder;

public class BCSignatureSpi extends SignatureSpi {
   protected BCSignatureSpi(Digest var1, DSA var2, DSAEncoder var3) {
      super(var1, var2, var3);
   }
}
