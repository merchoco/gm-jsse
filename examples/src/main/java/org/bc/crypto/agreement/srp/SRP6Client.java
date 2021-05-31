package org.bc.crypto.agreement.srp;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.CryptoException;
import org.bc.crypto.Digest;

public class SRP6Client {
   protected BigInteger N;
   protected BigInteger g;
   protected BigInteger a;
   protected BigInteger A;
   protected BigInteger B;
   protected BigInteger x;
   protected BigInteger u;
   protected BigInteger S;
   protected Digest digest;
   protected SecureRandom random;

   public void init(BigInteger var1, BigInteger var2, Digest var3, SecureRandom var4) {
      this.N = var1;
      this.g = var2;
      this.digest = var3;
      this.random = var4;
   }

   public BigInteger generateClientCredentials(byte[] var1, byte[] var2, byte[] var3) {
      this.x = SRP6Util.calculateX(this.digest, this.N, var1, var2, var3);
      this.a = this.selectPrivateValue();
      this.A = this.g.modPow(this.a, this.N);
      return this.A;
   }

   public BigInteger calculateSecret(BigInteger var1) throws CryptoException {
      this.B = SRP6Util.validatePublicValue(this.N, var1);
      this.u = SRP6Util.calculateU(this.digest, this.N, this.A, this.B);
      this.S = this.calculateS();
      return this.S;
   }

   protected BigInteger selectPrivateValue() {
      return SRP6Util.generatePrivateValue(this.digest, this.N, this.g, this.random);
   }

   private BigInteger calculateS() {
      BigInteger var1 = SRP6Util.calculateK(this.digest, this.N, this.g);
      BigInteger var2 = this.u.multiply(this.x).add(this.a);
      BigInteger var3 = this.g.modPow(this.x, this.N).multiply(var1).mod(this.N);
      return this.B.subtract(var3).mod(this.N).modPow(var2, this.N);
   }
}
