package org.bc.math.ec;

import java.math.BigInteger;
import java.util.Random;

public abstract class ECCurve {
   ECFieldElement a;
   ECFieldElement b;

   public abstract int getFieldSize();

   public abstract ECFieldElement fromBigInteger(BigInteger var1);

   public abstract ECPoint createPoint(BigInteger var1, BigInteger var2, boolean var3);

   public abstract ECPoint decodePoint(byte[] var1);

   public abstract ECPoint getInfinity();

   public ECFieldElement getA() {
      return this.a;
   }

   public ECFieldElement getB() {
      return this.b;
   }

   public static class F2m extends ECCurve {
      private int m;
      private int k1;
      private int k2;
      private int k3;
      private BigInteger n;
      private BigInteger h;
      private ECPoint.F2m infinity;
      private byte mu;
      private BigInteger[] si;

      public F2m(int var1, int var2, BigInteger var3, BigInteger var4) {
         this(var1, var2, 0, 0, var3, var4, (BigInteger)null, (BigInteger)null);
      }

      public F2m(int var1, int var2, BigInteger var3, BigInteger var4, BigInteger var5, BigInteger var6) {
         this(var1, var2, 0, 0, var3, var4, var5, var6);
      }

      public F2m(int var1, int var2, int var3, int var4, BigInteger var5, BigInteger var6) {
         this(var1, var2, var3, var4, var5, var6, (BigInteger)null, (BigInteger)null);
      }

      public F2m(int var1, int var2, int var3, int var4, BigInteger var5, BigInteger var6, BigInteger var7, BigInteger var8) {
         this.mu = 0;
         this.si = null;
         this.m = var1;
         this.k1 = var2;
         this.k2 = var3;
         this.k3 = var4;
         this.n = var7;
         this.h = var8;
         if (var2 == 0) {
            throw new IllegalArgumentException("k1 must be > 0");
         } else {
            if (var3 == 0) {
               if (var4 != 0) {
                  throw new IllegalArgumentException("k3 must be 0 if k2 == 0");
               }
            } else {
               if (var3 <= var2) {
                  throw new IllegalArgumentException("k2 must be > k1");
               }

               if (var4 <= var3) {
                  throw new IllegalArgumentException("k3 must be > k2");
               }
            }

            this.a = this.fromBigInteger(var5);
            this.b = this.fromBigInteger(var6);
            this.infinity = new ECPoint.F2m(this, (ECFieldElement)null, (ECFieldElement)null);
         }
      }

      public int getFieldSize() {
         return this.m;
      }

      public ECFieldElement fromBigInteger(BigInteger var1) {
         return new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, var1);
      }

      public ECPoint createPoint(BigInteger var1, BigInteger var2, boolean var3) {
         return new ECPoint.F2m(this, this.fromBigInteger(var1), this.fromBigInteger(var2), var3);
      }

      public ECPoint decodePoint(byte[] var1) {
         Object var2 = null;
         switch(var1[0]) {
         case 0:
            if (var1.length > 1) {
               throw new RuntimeException("Invalid point encoding");
            }

            var2 = this.getInfinity();
            break;
         case 1:
         case 5:
         default:
            throw new RuntimeException("Invalid point encoding 0x" + Integer.toString(var1[0], 16));
         case 2:
         case 3:
            byte[] var3 = new byte[var1.length - 1];
            System.arraycopy(var1, 1, var3, 0, var3.length);
            if (var1[0] == 2) {
               var2 = this.decompressPoint(var3, 0);
            } else {
               var2 = this.decompressPoint(var3, 1);
            }
            break;
         case 4:
         case 6:
         case 7:
            byte[] var4 = new byte[(var1.length - 1) / 2];
            byte[] var5 = new byte[(var1.length - 1) / 2];
            System.arraycopy(var1, 1, var4, 0, var4.length);
            System.arraycopy(var1, var4.length + 1, var5, 0, var5.length);
            var2 = new ECPoint.F2m(this, new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, new BigInteger(1, var4)), new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, new BigInteger(1, var5)), false);
         }

         return (ECPoint)var2;
      }

      public ECPoint getInfinity() {
         return this.infinity;
      }

      public boolean isKoblitz() {
         return this.n != null && this.h != null && (this.a.toBigInteger().equals(ECConstants.ZERO) || this.a.toBigInteger().equals(ECConstants.ONE)) && this.b.toBigInteger().equals(ECConstants.ONE);
      }

      synchronized byte getMu() {
         if (this.mu == 0) {
            this.mu = Tnaf.getMu(this);
         }

         return this.mu;
      }

      synchronized BigInteger[] getSi() {
         if (this.si == null) {
            this.si = Tnaf.getSi(this);
         }

         return this.si;
      }

      private ECPoint decompressPoint(byte[] var1, int var2) {
         ECFieldElement.F2m var3 = new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, new BigInteger(1, var1));
         Object var4 = null;
         if (var3.toBigInteger().equals(ECConstants.ZERO)) {
            var4 = (ECFieldElement.F2m)this.b;

            for(int var5 = 0; var5 < this.m - 1; ++var5) {
               var4 = ((ECFieldElement)var4).square();
            }
         } else {
            ECFieldElement var8 = var3.add(this.a).add(this.b.multiply(var3.square().invert()));
            ECFieldElement var6 = this.solveQuadradicEquation(var8);
            if (var6 == null) {
               throw new RuntimeException("Invalid point compression");
            }

            byte var7 = 0;
            if (var6.toBigInteger().testBit(0)) {
               var7 = 1;
            }

            if (var7 != var2) {
               var6 = var6.add(new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, ECConstants.ONE));
            }

            var4 = var3.multiply(var6);
         }

         return new ECPoint.F2m(this, var3, (ECFieldElement)var4);
      }

      private ECFieldElement solveQuadradicEquation(ECFieldElement var1) {
         ECFieldElement.F2m var2 = new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, ECConstants.ZERO);
         if (var1.toBigInteger().equals(ECConstants.ZERO)) {
            return var2;
         } else {
            Object var3 = null;
            Random var5 = new Random();

            ECFieldElement var4;
            do {
               ECFieldElement.F2m var6 = new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, new BigInteger(this.m, var5));
               var3 = var2;
               ECFieldElement var7 = var1;

               for(int var8 = 1; var8 <= this.m - 1; ++var8) {
                  ECFieldElement var9 = var7.square();
                  var3 = ((ECFieldElement)var3).square().add(var9.multiply(var6));
                  var7 = var9.add(var1);
               }

               if (!var7.toBigInteger().equals(ECConstants.ZERO)) {
                  return null;
               }

               var4 = ((ECFieldElement)var3).square().add((ECFieldElement)var3);
            } while(var4.toBigInteger().equals(ECConstants.ZERO));

            return (ECFieldElement)var3;
         }
      }

      public boolean equals(Object var1) {
         if (var1 == this) {
            return true;
         } else if (!(var1 instanceof ECCurve.F2m)) {
            return false;
         } else {
            ECCurve.F2m var2 = (ECCurve.F2m)var1;
            return this.m == var2.m && this.k1 == var2.k1 && this.k2 == var2.k2 && this.k3 == var2.k3 && this.a.equals(var2.a) && this.b.equals(var2.b);
         }
      }

      public int hashCode() {
         return this.a.hashCode() ^ this.b.hashCode() ^ this.m ^ this.k1 ^ this.k2 ^ this.k3;
      }

      public int getM() {
         return this.m;
      }

      public boolean isTrinomial() {
         return this.k2 == 0 && this.k3 == 0;
      }

      public int getK1() {
         return this.k1;
      }

      public int getK2() {
         return this.k2;
      }

      public int getK3() {
         return this.k3;
      }

      public BigInteger getN() {
         return this.n;
      }

      public BigInteger getH() {
         return this.h;
      }
   }

   public static class Fp extends ECCurve {
      BigInteger q;
      ECPoint.Fp infinity;

      public Fp(BigInteger var1, BigInteger var2, BigInteger var3) {
         this.q = var1;
         this.a = this.fromBigInteger(var2);
         this.b = this.fromBigInteger(var3);
         this.infinity = new ECPoint.Fp(this, (ECFieldElement)null, (ECFieldElement)null);
      }

      public BigInteger getQ() {
         return this.q;
      }

      public int getFieldSize() {
         return this.q.bitLength();
      }

      public ECFieldElement fromBigInteger(BigInteger var1) {
         return new ECFieldElement.Fp(this.q, var1);
      }

      public ECPoint createPoint(BigInteger var1, BigInteger var2, boolean var3) {
         return new ECPoint.Fp(this, this.fromBigInteger(var1), this.fromBigInteger(var2), var3);
      }

      public ECPoint decodePoint(byte[] var1) {
         Object var2 = null;
         switch(var1[0]) {
         case 0:
            if (var1.length > 1) {
               throw new RuntimeException("Invalid point encoding");
            }

            var2 = this.getInfinity();
            break;
         case 1:
         case 5:
         default:
            throw new RuntimeException("Invalid point encoding 0x" + Integer.toString(var1[0], 16));
         case 2:
         case 3:
            int var3 = var1[0] & 1;
            byte[] var4 = new byte[var1.length - 1];
            System.arraycopy(var1, 1, var4, 0, var4.length);
            ECFieldElement.Fp var5 = new ECFieldElement.Fp(this.q, new BigInteger(1, var4));
            ECFieldElement var6 = var5.multiply(var5.square().add(this.a)).add(this.b);
            ECFieldElement var7 = var6.sqrt();
            if (var7 == null) {
               throw new RuntimeException("Invalid point compression");
            }

            int var8 = var7.toBigInteger().testBit(0) ? 1 : 0;
            if (var8 == var3) {
               var2 = new ECPoint.Fp(this, var5, var7, true);
            } else {
               var2 = new ECPoint.Fp(this, var5, new ECFieldElement.Fp(this.q, this.q.subtract(var7.toBigInteger())), true);
            }
            break;
         case 4:
         case 6:
         case 7:
            byte[] var9 = new byte[(var1.length - 1) / 2];
            byte[] var10 = new byte[(var1.length - 1) / 2];
            System.arraycopy(var1, 1, var9, 0, var9.length);
            System.arraycopy(var1, var9.length + 1, var10, 0, var10.length);
            var2 = new ECPoint.Fp(this, new ECFieldElement.Fp(this.q, new BigInteger(1, var9)), new ECFieldElement.Fp(this.q, new BigInteger(1, var10)));
         }

         return (ECPoint)var2;
      }

      public ECPoint getInfinity() {
         return this.infinity;
      }

      public boolean equals(Object var1) {
         if (var1 == this) {
            return true;
         } else if (!(var1 instanceof ECCurve.Fp)) {
            return false;
         } else {
            ECCurve.Fp var2 = (ECCurve.Fp)var1;
            return this.q.equals(var2.q) && this.a.equals(var2.a) && this.b.equals(var2.b);
         }
      }

      public int hashCode() {
         return this.a.hashCode() ^ this.b.hashCode() ^ this.q.hashCode();
      }
   }
}
