package org.bc.pqc.crypto.mceliece;

import org.bc.crypto.Digest;
import org.bc.crypto.digests.SHA256Digest;

public class McElieceCCA2Parameters extends McElieceParameters {
   public Digest digest;

   public McElieceCCA2Parameters() {
      this.digest = new SHA256Digest();
   }

   public McElieceCCA2Parameters(int var1, int var2) {
      super(var1, var2);
      this.digest = new SHA256Digest();
   }

   public McElieceCCA2Parameters(Digest var1) {
      this.digest = var1;
   }

   public Digest getDigest() {
      return this.digest;
   }
}
