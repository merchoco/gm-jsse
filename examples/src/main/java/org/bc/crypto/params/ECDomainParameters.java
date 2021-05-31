package org.bc.crypto.params;

import java.math.BigInteger;
import org.bc.math.ec.ECConstants;
import org.bc.math.ec.ECCurve;
import org.bc.math.ec.ECPoint;

public class ECDomainParameters implements ECConstants {
   ECCurve curve;
   byte[] seed;
   ECPoint G;
   BigInteger n;
   BigInteger h;

   public ECDomainParameters(ECCurve var1, ECPoint var2, BigInteger var3) {
      this.curve = var1;
      this.G = var2;
      this.n = var3;
      this.h = ONE;
      this.seed = null;
   }

   public ECDomainParameters(ECCurve var1, ECPoint var2, BigInteger var3, BigInteger var4) {
      this.curve = var1;
      this.G = var2;
      this.n = var3;
      this.h = var4;
      this.seed = null;
   }

   public ECDomainParameters(ECCurve var1, ECPoint var2, BigInteger var3, BigInteger var4, byte[] var5) {
      this.curve = var1;
      this.G = var2;
      this.n = var3;
      this.h = var4;
      this.seed = var5;
   }

   public ECCurve getCurve() {
      return this.curve;
   }

   public ECPoint getG() {
      return this.G;
   }

   public BigInteger getN() {
      return this.n;
   }

   public BigInteger getH() {
      return this.h;
   }

   public byte[] getSeed() {
      return this.seed;
   }
}
