package org.bc.pqc.jcajce.spec;

import org.bc.pqc.crypto.gmss.GMSSParameters;

public class GMSSPublicKeySpec extends GMSSKeySpec {
   private byte[] gmssPublicKey;

   public GMSSPublicKeySpec(byte[] var1, GMSSParameters var2) {
      super(var2);
      this.gmssPublicKey = var1;
   }

   public byte[] getPublicKey() {
      return this.gmssPublicKey;
   }
}
