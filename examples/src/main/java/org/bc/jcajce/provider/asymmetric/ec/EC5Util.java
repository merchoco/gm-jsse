package org.bc.jcajce.provider.asymmetric.ec;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import org.bc.jce.spec.ECNamedCurveParameterSpec;
import org.bc.jce.spec.ECNamedCurveSpec;
import org.bc.math.ec.ECCurve;

public class EC5Util {
   public static EllipticCurve convertCurve(ECCurve var0, byte[] var1) {
      if (var0 instanceof ECCurve.Fp) {
         return new EllipticCurve(new ECFieldFp(((ECCurve.Fp)var0).getQ()), var0.getA().toBigInteger(), var0.getB().toBigInteger(), (byte[])null);
      } else {
         ECCurve.F2m var2 = (ECCurve.F2m)var0;
         int[] var3;
         if (var2.isTrinomial()) {
            var3 = new int[]{var2.getK1()};
            return new EllipticCurve(new ECFieldF2m(var2.getM(), var3), var0.getA().toBigInteger(), var0.getB().toBigInteger(), (byte[])null);
         } else {
            var3 = new int[]{var2.getK3(), var2.getK2(), var2.getK1()};
            return new EllipticCurve(new ECFieldF2m(var2.getM(), var3), var0.getA().toBigInteger(), var0.getB().toBigInteger(), (byte[])null);
         }
      }
   }

   public static ECCurve convertCurve(EllipticCurve var0) {
      ECField var1 = var0.getField();
      BigInteger var2 = var0.getA();
      BigInteger var3 = var0.getB();
      if (var1 instanceof ECFieldFp) {
         return new ECCurve.Fp(((ECFieldFp)var1).getP(), var2, var3);
      } else {
         ECFieldF2m var4 = (ECFieldF2m)var1;
         int var5 = var4.getM();
         int[] var6 = ECUtil.convertMidTerms(var4.getMidTermsOfReductionPolynomial());
         return new ECCurve.F2m(var5, var6[0], var6[1], var6[2], var2, var3);
      }
   }

   public static ECParameterSpec convertSpec(EllipticCurve var0, org.bc.jce.spec.ECParameterSpec var1) {
      return (ECParameterSpec)(var1 instanceof ECNamedCurveParameterSpec ? new ECNamedCurveSpec(((ECNamedCurveParameterSpec)var1).getName(), var0, new ECPoint(var1.getG().getX().toBigInteger(), var1.getG().getY().toBigInteger()), var1.getN(), var1.getH()) : new ECParameterSpec(var0, new ECPoint(var1.getG().getX().toBigInteger(), var1.getG().getY().toBigInteger()), var1.getN(), var1.getH().intValue()));
   }

   public static org.bc.jce.spec.ECParameterSpec convertSpec(ECParameterSpec var0, boolean var1) {
      ECCurve var2 = convertCurve(var0.getCurve());
      return new org.bc.jce.spec.ECParameterSpec(var2, convertPoint(var2, var0.getGenerator(), var1), var0.getOrder(), BigInteger.valueOf((long)var0.getCofactor()), var0.getCurve().getSeed());
   }

   public static org.bc.math.ec.ECPoint convertPoint(ECParameterSpec var0, ECPoint var1, boolean var2) {
      return convertPoint(convertCurve(var0.getCurve()), var1, var2);
   }

   public static org.bc.math.ec.ECPoint convertPoint(ECCurve var0, ECPoint var1, boolean var2) {
      return var0.createPoint(var1.getAffineX(), var1.getAffineY(), var2);
   }
}
