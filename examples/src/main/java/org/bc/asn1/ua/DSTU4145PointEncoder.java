package org.bc.asn1.ua;

import java.math.BigInteger;
import java.util.Random;
import org.bc.asn1.x9.X9IntegerConverter;
import org.bc.math.ec.ECConstants;
import org.bc.math.ec.ECCurve;
import org.bc.math.ec.ECFieldElement;
import org.bc.math.ec.ECPoint;
import org.bc.util.Arrays;

public abstract class DSTU4145PointEncoder {
   private static X9IntegerConverter converter = new X9IntegerConverter();

   private static BigInteger trace(ECFieldElement var0) {
      ECFieldElement var1 = var0;

      for(int var2 = 0; var2 < var0.getFieldSize() - 1; ++var2) {
         var1 = var1.square().add(var0);
      }

      return var1.toBigInteger();
   }

   private static ECFieldElement solveQuadradicEquation(ECFieldElement var0) {
      ECFieldElement.F2m var1 = (ECFieldElement.F2m)var0;
      ECFieldElement.F2m var2 = new ECFieldElement.F2m(var1.getM(), var1.getK1(), var1.getK2(), var1.getK3(), ECConstants.ZERO);
      if (var0.toBigInteger().equals(ECConstants.ZERO)) {
         return var2;
      } else {
         Object var3 = null;
         Random var5 = new Random();
         int var6 = var1.getM();

         ECFieldElement var4;
         do {
            ECFieldElement.F2m var7 = new ECFieldElement.F2m(var1.getM(), var1.getK1(), var1.getK2(), var1.getK3(), new BigInteger(var6, var5));
            var3 = var2;
            ECFieldElement var8 = var0;

            for(int var9 = 1; var9 <= var6 - 1; ++var9) {
               ECFieldElement var10 = var8.square();
               var3 = ((ECFieldElement)var3).square().add(var10.multiply(var7));
               var8 = var10.add(var0);
            }

            if (!var8.toBigInteger().equals(ECConstants.ZERO)) {
               return null;
            }

            var4 = ((ECFieldElement)var3).square().add((ECFieldElement)var3);
         } while(var4.toBigInteger().equals(ECConstants.ZERO));

         return (ECFieldElement)var3;
      }
   }

   public static byte[] encodePoint(ECPoint var0) {
      int var1 = converter.getByteLength(var0.getX());
      byte[] var2 = converter.integerToBytes(var0.getX().toBigInteger(), var1);
      if (!var0.getX().toBigInteger().equals(ECConstants.ZERO)) {
         ECFieldElement var3 = var0.getY().multiply(var0.getX().invert());
         if (trace(var3).equals(ECConstants.ONE)) {
            var2[var2.length - 1] = (byte)(var2[var2.length - 1] | 1);
         } else {
            var2[var2.length - 1] = (byte)(var2[var2.length - 1] & 254);
         }
      }

      return var2;
   }

   public static ECPoint decodePoint(ECCurve var0, byte[] var1) {
      BigInteger var2 = BigInteger.valueOf((long)(var1[var1.length - 1] & 1));
      if (!trace(var0.fromBigInteger(new BigInteger(1, var1))).equals(var0.getA().toBigInteger())) {
         var1 = Arrays.clone(var1);
         var1[var1.length - 1] = (byte)(var1[var1.length - 1] ^ 1);
      }

      ECCurve.F2m var3 = (ECCurve.F2m)var0;
      ECFieldElement var4 = var0.fromBigInteger(new BigInteger(1, var1));
      Object var5 = null;
      if (var4.toBigInteger().equals(ECConstants.ZERO)) {
         var5 = (ECFieldElement.F2m)var0.getB();

         for(int var6 = 0; var6 < var3.getM() - 1; ++var6) {
            var5 = ((ECFieldElement)var5).square();
         }
      } else {
         ECFieldElement var8 = var4.add(var0.getA()).add(var0.getB().multiply(var4.square().invert()));
         ECFieldElement var7 = solveQuadradicEquation(var8);
         if (var7 == null) {
            throw new RuntimeException("Invalid point compression");
         }

         if (!trace(var7).equals(var2)) {
            var7 = var7.add(var0.fromBigInteger(ECConstants.ONE));
         }

         var5 = var4.multiply(var7);
      }

      return new ECPoint.F2m(var0, var4, (ECFieldElement)var5);
   }
}
