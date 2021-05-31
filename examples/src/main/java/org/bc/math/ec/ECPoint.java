package org.bc.math.ec;

import java.math.BigInteger;
import org.bc.asn1.x9.X9IntegerConverter;

public abstract class ECPoint {
   ECCurve curve;
   ECFieldElement x;
   ECFieldElement y;
   protected boolean withCompression;
   protected ECMultiplier multiplier = null;
   protected PreCompInfo preCompInfo = null;
   private static X9IntegerConverter converter = new X9IntegerConverter();
   public static long counter = 0L;

   protected ECPoint(ECCurve var1, ECFieldElement var2, ECFieldElement var3) {
      this.curve = var1;
      this.x = var2;
      this.y = var3;
   }

   public ECCurve getCurve() {
      return this.curve;
   }

   public ECFieldElement getX() {
      return this.x;
   }

   public ECFieldElement getY() {
      return this.y;
   }

   public boolean isInfinity() {
      return this.x == null && this.y == null;
   }

   public boolean isCompressed() {
      return this.withCompression;
   }

   public boolean equals(Object var1) {
      if (var1 == this) {
         return true;
      } else if (!(var1 instanceof ECPoint)) {
         return false;
      } else {
         ECPoint var2 = (ECPoint)var1;
         if (this.isInfinity()) {
            return var2.isInfinity();
         } else {
            return this.x.equals(var2.x) && this.y.equals(var2.y);
         }
      }
   }

   public int hashCode() {
      return this.isInfinity() ? 0 : this.x.hashCode() ^ this.y.hashCode();
   }

   void setPreCompInfo(PreCompInfo var1) {
      this.preCompInfo = var1;
   }

   public abstract byte[] getEncoded();

   public abstract ECPoint add(ECPoint var1);

   public abstract ECPoint subtract(ECPoint var1);

   public abstract ECPoint negate();

   public abstract ECPoint twice();

   synchronized void assertECMultiplier() {
      if (this.multiplier == null) {
         this.multiplier = new FpNafMultiplier();
      }

   }

   public ECPoint multiply(BigInteger var1) {
      if (var1.signum() < 0) {
         throw new IllegalArgumentException("The multiplicator cannot be negative");
      } else if (this.isInfinity()) {
         return this;
      } else if (var1.signum() == 0) {
         return this.curve.getInfinity();
      } else {
         this.assertECMultiplier();
         return this.multiplier.multiply(this, var1, this.preCompInfo);
      }
   }

   public static class F2m extends ECPoint {
      public F2m(ECCurve var1, ECFieldElement var2, ECFieldElement var3) {
         this(var1, var2, var3, false);
      }

      public F2m(ECCurve var1, ECFieldElement var2, ECFieldElement var3, boolean var4) {
         super(var1, var2, var3);
         if ((var2 == null || var3 != null) && (var2 != null || var3 == null)) {
            if (var2 != null) {
               ECFieldElement.F2m.checkFieldElements(this.x, this.y);
               if (var1 != null) {
                  ECFieldElement.F2m.checkFieldElements(this.x, this.curve.getA());
               }
            }

            this.withCompression = var4;
         } else {
            throw new IllegalArgumentException("Exactly one of the field elements is null");
         }
      }

      public byte[] getEncoded() {
         if (this.isInfinity()) {
            return new byte[1];
         } else {
            int var1 = ECPoint.converter.getByteLength(this.x);
            byte[] var2 = ECPoint.converter.integerToBytes(this.getX().toBigInteger(), var1);
            byte[] var3;
            if (this.withCompression) {
               var3 = new byte[var1 + 1];
               var3[0] = 2;
               if (!this.getX().toBigInteger().equals(ECConstants.ZERO) && this.getY().multiply(this.getX().invert()).toBigInteger().testBit(0)) {
                  var3[0] = 3;
               }

               System.arraycopy(var2, 0, var3, 1, var1);
            } else {
               byte[] var4 = ECPoint.converter.integerToBytes(this.getY().toBigInteger(), var1);
               var3 = new byte[var1 + var1 + 1];
               var3[0] = 4;
               System.arraycopy(var2, 0, var3, 1, var1);
               System.arraycopy(var4, 0, var3, var1 + 1, var1);
            }

            return var3;
         }
      }

      private static void checkPoints(ECPoint var0, ECPoint var1) {
         if (!var0.curve.equals(var1.curve)) {
            throw new IllegalArgumentException("Only points on the same curve can be added or subtracted");
         }
      }

      public ECPoint add(ECPoint var1) {
         checkPoints(this, var1);
         return this.addSimple((ECPoint.F2m)var1);
      }

      public ECPoint.F2m addSimple(ECPoint.F2m var1) {
         if (this.isInfinity()) {
            return var1;
         } else if (var1.isInfinity()) {
            return this;
         } else {
            ECFieldElement.F2m var3 = (ECFieldElement.F2m)var1.getX();
            ECFieldElement.F2m var4 = (ECFieldElement.F2m)var1.getY();
            if (this.x.equals(var3)) {
               return this.y.equals(var4) ? (ECPoint.F2m)this.twice() : (ECPoint.F2m)this.curve.getInfinity();
            } else {
               ECFieldElement.F2m var5 = (ECFieldElement.F2m)this.y.add(var4).divide(this.x.add(var3));
               ECFieldElement.F2m var6 = (ECFieldElement.F2m)var5.square().add(var5).add(this.x).add(var3).add(this.curve.getA());
               ECFieldElement.F2m var7 = (ECFieldElement.F2m)var5.multiply(this.x.add(var6)).add(var6).add(this.y);
               return new ECPoint.F2m(this.curve, var6, var7, this.withCompression);
            }
         }
      }

      public ECPoint subtract(ECPoint var1) {
         checkPoints(this, var1);
         return this.subtractSimple((ECPoint.F2m)var1);
      }

      public ECPoint.F2m subtractSimple(ECPoint.F2m var1) {
         return var1.isInfinity() ? this : this.addSimple((ECPoint.F2m)var1.negate());
      }

      public ECPoint twice() {
         if (this.isInfinity()) {
            return this;
         } else if (this.x.toBigInteger().signum() == 0) {
            return this.curve.getInfinity();
         } else {
            ECFieldElement.F2m var1 = (ECFieldElement.F2m)this.x.add(this.y.divide(this.x));
            ECFieldElement.F2m var2 = (ECFieldElement.F2m)var1.square().add(var1).add(this.curve.getA());
            ECFieldElement var3 = this.curve.fromBigInteger(ECConstants.ONE);
            ECFieldElement.F2m var4 = (ECFieldElement.F2m)this.x.square().add(var2.multiply(var1.add(var3)));
            return new ECPoint.F2m(this.curve, var2, var4, this.withCompression);
         }
      }

      public ECPoint negate() {
         return new ECPoint.F2m(this.curve, this.getX(), this.getY().add(this.getX()), this.withCompression);
      }

      synchronized void assertECMultiplier() {
         if (this.multiplier == null) {
            if (((ECCurve.F2m)this.curve).isKoblitz()) {
               this.multiplier = new WTauNafMultiplier();
            } else {
               this.multiplier = new WNafMultiplier();
            }
         }

      }
   }

   public static class Fp extends ECPoint {
      public Fp(ECCurve var1, ECFieldElement var2, ECFieldElement var3) {
         this(var1, var2, var3, false);
      }

      public Fp(ECCurve var1, ECFieldElement var2, ECFieldElement var3, boolean var4) {
         super(var1, var2, var3);
         if ((var2 == null || var3 != null) && (var2 != null || var3 == null)) {
            this.withCompression = var4;
         } else {
            throw new IllegalArgumentException("Exactly one of the field elements is null");
         }
      }

      public byte[] getEncoded() {
         if (this.isInfinity()) {
            return new byte[1];
         } else {
            int var1 = ECPoint.converter.getByteLength(this.x);
            byte[] var3;
            byte[] var4;
            if (this.withCompression) {
               byte var5;
               if (this.getY().toBigInteger().testBit(0)) {
                  var5 = 3;
               } else {
                  var5 = 2;
               }

               var3 = ECPoint.converter.integerToBytes(this.getX().toBigInteger(), var1);
               var4 = new byte[var3.length + 1];
               var4[0] = var5;
               System.arraycopy(var3, 0, var4, 1, var3.length);
               return var4;
            } else {
               byte[] var2 = ECPoint.converter.integerToBytes(this.getX().toBigInteger(), var1);
               var3 = ECPoint.converter.integerToBytes(this.getY().toBigInteger(), var1);
               var4 = new byte[var2.length + var3.length + 1];
               var4[0] = 4;
               System.arraycopy(var2, 0, var4, 1, var2.length);
               System.arraycopy(var3, 0, var4, var2.length + 1, var3.length);
               return var4;
            }
         }
      }

      public ECPoint add(ECPoint var1) {
         if (this.isInfinity()) {
            return var1;
         } else if (var1.isInfinity()) {
            return this;
         } else if (this.x.equals(var1.x)) {
            return this.y.equals(var1.y) ? this.twice() : this.curve.getInfinity();
         } else {
            ECFieldElement var2 = var1.y.subtract(this.y).divide(var1.x.subtract(this.x));
            ECFieldElement var3 = var2.square().subtract(this.x).subtract(var1.x);
            ECFieldElement var4 = var2.multiply(this.x.subtract(var3)).subtract(this.y);
            return new ECPoint.Fp(this.curve, var3, var4);
         }
      }

      public ECPoint twice() {
         if (this.isInfinity()) {
            return this;
         } else if (this.y.toBigInteger().signum() == 0) {
            return this.curve.getInfinity();
         } else {
            ECFieldElement var1 = this.curve.fromBigInteger(BigInteger.valueOf(2L));
            ECFieldElement var2 = this.curve.fromBigInteger(BigInteger.valueOf(3L));
            ECFieldElement var3 = this.x.square().multiply(var2).add(this.curve.a).divide(this.y.multiply(var1));
            ECFieldElement var4 = var3.square().subtract(this.x.multiply(var1));
            ECFieldElement var5 = var3.multiply(this.x.subtract(var4)).subtract(this.y);
            return new ECPoint.Fp(this.curve, var4, var5, this.withCompression);
         }
      }

      public ECPoint subtract(ECPoint var1) {
         return (ECPoint)(var1.isInfinity() ? this : this.add(var1.negate()));
      }

      public ECPoint negate() {
         return new ECPoint.Fp(this.curve, this.x, this.y.negate(), this.withCompression);
      }

      synchronized void assertECMultiplier() {
         if (this.multiplier == null) {
            this.multiplier = new WNafMultiplier();
         }

      }
   }
}
