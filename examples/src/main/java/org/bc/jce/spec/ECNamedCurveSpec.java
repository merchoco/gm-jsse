package org.bc.jce.spec;

import java.math.BigInteger;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import org.bc.math.ec.ECCurve;

public class ECNamedCurveSpec extends java.security.spec.ECParameterSpec {
   private String name;

   private static EllipticCurve convertCurve(ECCurve var0, byte[] var1) {
      if (var0 instanceof ECCurve.Fp) {
         return new EllipticCurve(new ECFieldFp(((ECCurve.Fp)var0).getQ()), var0.getA().toBigInteger(), var0.getB().toBigInteger(), var1);
      } else {
         ECCurve.F2m var2 = (ECCurve.F2m)var0;
         int[] var3;
         if (var2.isTrinomial()) {
            var3 = new int[]{var2.getK1()};
            return new EllipticCurve(new ECFieldF2m(var2.getM(), var3), var0.getA().toBigInteger(), var0.getB().toBigInteger(), var1);
         } else {
            var3 = new int[]{var2.getK3(), var2.getK2(), var2.getK1()};
            return new EllipticCurve(new ECFieldF2m(var2.getM(), var3), var0.getA().toBigInteger(), var0.getB().toBigInteger(), var1);
         }
      }
   }

   private static ECPoint convertPoint(org.bc.math.ec.ECPoint var0) {
      return new ECPoint(var0.getX().toBigInteger(), var0.getY().toBigInteger());
   }

   public ECNamedCurveSpec(String var1, ECCurve var2, org.bc.math.ec.ECPoint var3, BigInteger var4) {
      super(convertCurve(var2, (byte[])null), convertPoint(var3), var4, 1);
      this.name = var1;
   }

   public ECNamedCurveSpec(String var1, EllipticCurve var2, ECPoint var3, BigInteger var4) {
      super(var2, var3, var4, 1);
      this.name = var1;
   }

   public ECNamedCurveSpec(String var1, ECCurve var2, org.bc.math.ec.ECPoint var3, BigInteger var4, BigInteger var5) {
      super(convertCurve(var2, (byte[])null), convertPoint(var3), var4, var5.intValue());
      this.name = var1;
   }

   public ECNamedCurveSpec(String var1, EllipticCurve var2, ECPoint var3, BigInteger var4, BigInteger var5) {
      super(var2, var3, var4, var5.intValue());
      this.name = var1;
   }

   public ECNamedCurveSpec(String var1, ECCurve var2, org.bc.math.ec.ECPoint var3, BigInteger var4, BigInteger var5, byte[] var6) {
      super(convertCurve(var2, var6), convertPoint(var3), var4, var5.intValue());
      this.name = var1;
   }

   public String getName() {
      return this.name;
   }
}
