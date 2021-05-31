package org.bc.crypto.agreement.srp;

import java.math.BigInteger;
import org.bc.crypto.Digest;

public class SRP6VerifierGenerator {
   protected BigInteger N;
   protected BigInteger g;
   protected Digest digest;

   public void init(BigInteger var1, BigInteger var2, Digest var3) {
      this.N = var1;
      this.g = var2;
      this.digest = var3;
   }

   public BigInteger generateVerifier(byte[] var1, byte[] var2, byte[] var3) {
      BigInteger var4 = SRP6Util.calculateX(this.digest, this.N, var1, var2, var3);
      return this.g.modPow(var4, this.N);
   }
}
