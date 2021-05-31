package org.bc.math.ec;

import java.math.BigInteger;
import java.util.Random;

public abstract class ECFieldElement implements ECConstants {
   public abstract BigInteger toBigInteger();

   public abstract String getFieldName();

   public abstract int getFieldSize();

   public abstract ECFieldElement add(ECFieldElement var1);

   public abstract ECFieldElement subtract(ECFieldElement var1);

   public abstract ECFieldElement multiply(ECFieldElement var1);

   public abstract ECFieldElement divide(ECFieldElement var1);

   public abstract ECFieldElement negate();

   public abstract ECFieldElement square();

   public abstract ECFieldElement invert();

   public abstract ECFieldElement sqrt();

   public String toString() {
      return this.toBigInteger().toString(2);
   }

   public static class F2m extends ECFieldElement {
      public static final int GNB = 1;
      public static final int TPB = 2;
      public static final int PPB = 3;
      private int representation;
      private int m;
      private int k1;
      private int k2;
      private int k3;
      private IntArray x;
      private int t;

      public F2m(int var1, int var2, int var3, int var4, BigInteger var5) {
         this.t = var1 + 31 >> 5;
         this.x = new IntArray(var5, this.t);
         if (var3 == 0 && var4 == 0) {
            this.representation = 2;
         } else {
            if (var3 >= var4) {
               throw new IllegalArgumentException("k2 must be smaller than k3");
            }

            if (var3 <= 0) {
               throw new IllegalArgumentException("k2 must be larger than 0");
            }

            this.representation = 3;
         }

         if (var5.signum() < 0) {
            throw new IllegalArgumentException("x value cannot be negative");
         } else {
            this.m = var1;
            this.k1 = var2;
            this.k2 = var3;
            this.k3 = var4;
         }
      }

      public F2m(int var1, int var2, BigInteger var3) {
         this(var1, var2, 0, 0, (BigInteger)var3);
      }

      private F2m(int var1, int var2, int var3, int var4, IntArray var5) {
         this.t = var1 + 31 >> 5;
         this.x = var5;
         this.m = var1;
         this.k1 = var2;
         this.k2 = var3;
         this.k3 = var4;
         if (var3 == 0 && var4 == 0) {
            this.representation = 2;
         } else {
            this.representation = 3;
         }

      }

      public BigInteger toBigInteger() {
         return this.x.toBigInteger();
      }

      public String getFieldName() {
         return "F2m";
      }

      public int getFieldSize() {
         return this.m;
      }

      public static void checkFieldElements(ECFieldElement var0, ECFieldElement var1) {
         if (var0 instanceof ECFieldElement.F2m && var1 instanceof ECFieldElement.F2m) {
            ECFieldElement.F2m var2 = (ECFieldElement.F2m)var0;
            ECFieldElement.F2m var3 = (ECFieldElement.F2m)var1;
            if (var2.m == var3.m && var2.k1 == var3.k1 && var2.k2 == var3.k2 && var2.k3 == var3.k3) {
               if (var2.representation != var3.representation) {
                  throw new IllegalArgumentException("One of the field elements are not elements has incorrect representation");
               }
            } else {
               throw new IllegalArgumentException("Field elements are not elements of the same field F2m");
            }
         } else {
            throw new IllegalArgumentException("Field elements are not both instances of ECFieldElement.F2m");
         }
      }

      public ECFieldElement add(ECFieldElement var1) {
         IntArray var2 = (IntArray)this.x.clone();
         ECFieldElement.F2m var3 = (ECFieldElement.F2m)var1;
         var2.addShifted(var3.x, 0);
         return new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, var2);
      }

      public ECFieldElement subtract(ECFieldElement var1) {
         return this.add(var1);
      }

      public ECFieldElement multiply(ECFieldElement var1) {
         ECFieldElement.F2m var2 = (ECFieldElement.F2m)var1;
         IntArray var3 = this.x.multiply(var2.x, this.m);
         var3.reduce(this.m, new int[]{this.k1, this.k2, this.k3});
         return new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, var3);
      }

      public ECFieldElement divide(ECFieldElement var1) {
         ECFieldElement var2 = var1.invert();
         return this.multiply(var2);
      }

      public ECFieldElement negate() {
         return this;
      }

      public ECFieldElement square() {
         IntArray var1 = this.x.square(this.m);
         var1.reduce(this.m, new int[]{this.k1, this.k2, this.k3});
         return new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, var1);
      }

      public ECFieldElement invert() {
         IntArray var1 = (IntArray)this.x.clone();
         IntArray var2 = new IntArray(this.t);
         var2.setBit(this.m);
         var2.setBit(0);
         var2.setBit(this.k1);
         if (this.representation == 3) {
            var2.setBit(this.k2);
            var2.setBit(this.k3);
         }

         IntArray var3 = new IntArray(this.t);
         var3.setBit(0);
         IntArray var4 = new IntArray(this.t);

         while(!var1.isZero()) {
            int var5 = var1.bitLength() - var2.bitLength();
            if (var5 < 0) {
               IntArray var6 = var1;
               var1 = var2;
               var2 = var6;
               IntArray var7 = var3;
               var3 = var4;
               var4 = var7;
               var5 = -var5;
            }

            int var10 = var5 >> 5;
            int var11 = var5 & 31;
            IntArray var8 = var2.shiftLeft(var11);
            var1.addShifted(var8, var10);
            IntArray var9 = var4.shiftLeft(var11);
            var3.addShifted(var9, var10);
         }

         return new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, var4);
      }

      public ECFieldElement sqrt() {
         throw new RuntimeException("Not implemented");
      }

      public int getRepresentation() {
         return this.representation;
      }

      public int getM() {
         return this.m;
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

      public boolean equals(Object var1) {
         if (var1 == this) {
            return true;
         } else if (!(var1 instanceof ECFieldElement.F2m)) {
            return false;
         } else {
            ECFieldElement.F2m var2 = (ECFieldElement.F2m)var1;
            return this.m == var2.m && this.k1 == var2.k1 && this.k2 == var2.k2 && this.k3 == var2.k3 && this.representation == var2.representation && this.x.equals(var2.x);
         }
      }

      public int hashCode() {
         return this.x.hashCode() ^ this.m ^ this.k1 ^ this.k2 ^ this.k3;
      }
   }

   public static class Fp extends ECFieldElement {
      BigInteger x;
      BigInteger q;

      public Fp(BigInteger var1, BigInteger var2) {
         this.x = var2;
         if (var2.compareTo(var1) >= 0) {
            throw new IllegalArgumentException("x value too large in field element");
         } else {
            this.q = var1;
         }
      }

      public BigInteger toBigInteger() {
         return this.x;
      }

      public String getFieldName() {
         return "Fp";
      }

      public int getFieldSize() {
         return this.q.bitLength();
      }

      public BigInteger getQ() {
         return this.q;
      }

      public ECFieldElement add(ECFieldElement var1) {
         return new ECFieldElement.Fp(this.q, this.x.add(var1.toBigInteger()).mod(this.q));
      }

      public ECFieldElement subtract(ECFieldElement var1) {
         return new ECFieldElement.Fp(this.q, this.x.subtract(var1.toBigInteger()).mod(this.q));
      }

      public ECFieldElement multiply(ECFieldElement var1) {
         return new ECFieldElement.Fp(this.q, this.x.multiply(var1.toBigInteger()).mod(this.q));
      }

      public ECFieldElement divide(ECFieldElement var1) {
         return new ECFieldElement.Fp(this.q, this.x.multiply(var1.toBigInteger().modInverse(this.q)).mod(this.q));
      }

      public ECFieldElement negate() {
         return new ECFieldElement.Fp(this.q, this.x.negate().mod(this.q));
      }

      public ECFieldElement square() {
         return new ECFieldElement.Fp(this.q, this.x.multiply(this.x).mod(this.q));
      }

      public ECFieldElement invert() {
         return new ECFieldElement.Fp(this.q, this.x.modInverse(this.q));
      }

      public ECFieldElement sqrt() {
         if (!this.q.testBit(0)) {
            throw new RuntimeException("not done yet");
         } else if (this.q.testBit(1)) {
            ECFieldElement.Fp var12 = new ECFieldElement.Fp(this.q, this.x.modPow(this.q.shiftRight(2).add(ECConstants.ONE), this.q));
            return var12.square().equals(this) ? var12 : null;
         } else {
            BigInteger var1 = this.q.subtract(ECConstants.ONE);
            BigInteger var2 = var1.shiftRight(1);
            if (!this.x.modPow(var2, this.q).equals(ECConstants.ONE)) {
               return null;
            } else {
               BigInteger var3 = var1.shiftRight(2);
               BigInteger var4 = var3.shiftLeft(1).add(ECConstants.ONE);
               BigInteger var5 = this.x;
               BigInteger var6 = var5.shiftLeft(2).mod(this.q);
               Random var9 = new Random();

               while(true) {
                  BigInteger var10;
                  do {
                     var10 = new BigInteger(this.q.bitLength(), var9);
                  } while(var10.compareTo(this.q) >= 0);

                  if (var10.multiply(var10).subtract(var6).modPow(var2, this.q).equals(var1)) {
                     BigInteger[] var11 = lucasSequence(this.q, var10, var5, var4);
                     BigInteger var7 = var11[0];
                     BigInteger var8 = var11[1];
                     if (var8.multiply(var8).mod(this.q).equals(var6)) {
                        if (var8.testBit(0)) {
                           var8 = var8.add(this.q);
                        }

                        var8 = var8.shiftRight(1);
                        return new ECFieldElement.Fp(this.q, var8);
                     }

                     if (!var7.equals(ECConstants.ONE) && !var7.equals(var1)) {
                        return null;
                     }
                  }
               }
            }
         }
      }

      private static BigInteger[] lucasSequence(BigInteger var0, BigInteger var1, BigInteger var2, BigInteger var3) {
         int var4 = var3.bitLength();
         int var5 = var3.getLowestSetBit();
         BigInteger var6 = ECConstants.ONE;
         BigInteger var7 = ECConstants.TWO;
         BigInteger var8 = var1;
         BigInteger var9 = ECConstants.ONE;
         BigInteger var10 = ECConstants.ONE;

         int var11;
         for(var11 = var4 - 1; var11 >= var5 + 1; --var11) {
            var9 = var9.multiply(var10).mod(var0);
            if (var3.testBit(var11)) {
               var10 = var9.multiply(var2).mod(var0);
               var6 = var6.multiply(var8).mod(var0);
               var7 = var8.multiply(var7).subtract(var1.multiply(var9)).mod(var0);
               var8 = var8.multiply(var8).subtract(var10.shiftLeft(1)).mod(var0);
            } else {
               var10 = var9;
               var6 = var6.multiply(var7).subtract(var9).mod(var0);
               var8 = var8.multiply(var7).subtract(var1.multiply(var9)).mod(var0);
               var7 = var7.multiply(var7).subtract(var9.shiftLeft(1)).mod(var0);
            }
         }

         var9 = var9.multiply(var10).mod(var0);
         var10 = var9.multiply(var2).mod(var0);
         var6 = var6.multiply(var7).subtract(var9).mod(var0);
         var7 = var8.multiply(var7).subtract(var1.multiply(var9)).mod(var0);
         var9 = var9.multiply(var10).mod(var0);

         for(var11 = 1; var11 <= var5; ++var11) {
            var6 = var6.multiply(var7).mod(var0);
            var7 = var7.multiply(var7).subtract(var9.shiftLeft(1)).mod(var0);
            var9 = var9.multiply(var9).mod(var0);
         }

         return new BigInteger[]{var6, var7};
      }

      public boolean equals(Object var1) {
         if (var1 == this) {
            return true;
         } else if (!(var1 instanceof ECFieldElement.Fp)) {
            return false;
         } else {
            ECFieldElement.Fp var2 = (ECFieldElement.Fp)var1;
            return this.q.equals(var2.q) && this.x.equals(var2.x);
         }
      }

      public int hashCode() {
         return this.q.hashCode() ^ this.x.hashCode();
      }
   }
}
