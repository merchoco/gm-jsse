package org.bc.crypto.agreement.srp;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.CryptoException;
import org.bc.crypto.Digest;

public class SRP6Server {
   protected BigInteger N;
   protected BigInteger g;
   protected BigInteger v;
   protected SecureRandom random;
   protected Digest digest;
   protected BigInteger A;
   protected BigInteger b;
   protected BigInteger B;
   protected BigInteger u;
   protected BigInteger S;

   public void init(BigInteger var1, BigInteger var2, BigInteger var3, Digest var4, SecureRandom var5) {
      this.N = var1;
      this.g = var2;
      this.v = var3;
      this.random = var5;
      this.digest = var4;
   }

   public BigInteger generateServerCredentials() {
      BigInteger var1 = SRP6Util.calculateK(this.digest, this.N, this.g);
      this.b = this.selectPrivateValue();
      this.B = var1.multiply(this.v).mod(this.N).add(this.g.modPow(this.b, this.N)).mod(this.N);
      return this.B;
   }

   public BigInteger calculateSecret(BigInteger var1) throws CryptoException {
      this.A = SRP6Util.validatePublicValue(this.N, var1);
      this.u = SRP6Util.calculateU(this.digest, this.N, this.A, this.B);
      this.S = this.calculateS();
      return this.S;
   }

   protected BigInteger selectPrivateValue() {
      return SRP6Util.generatePrivateValue(this.digest, this.N, this.g, this.random);
   }

   private BigInteger calculateS() {
      return this.v.modPow(this.u, this.N).multiply(this.A).mod(this.N).modPow(this.b, this.N);
   }
}
