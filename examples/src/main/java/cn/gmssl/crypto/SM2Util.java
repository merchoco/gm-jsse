package cn.gmssl.crypto;

import java.math.BigInteger;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import org.bc.jce.spec.ECNamedCurveParameterSpec;
import org.bc.jce.spec.ECParameterSpec;
import org.bc.math.ec.ECCurve;
import org.bc.math.ec.ECPoint;

class SM2Util {
   public static BigInteger p = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
   public static BigInteger a = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
   public static BigInteger b = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
   public static BigInteger xG = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
   public static BigInteger yG = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
   public static BigInteger n = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
   public static int m = 257;
   public static int k = 12;
   public static String OID_SM3WITHSM2 = "1.2.156.10197.1.501";
   public static String OID_SM2_PUBLICKEY = "1.2.840.10045.2.1";
   public static String OID_SM2_256CURVE = "1.2.156.10197.1.301";

   public static ECParameterSpec getSM2ParamSpec() {
      ECCurve.Fp var0 = new ECCurve.Fp(p, a, b);
      ECPoint var1 = var0.createPoint(xG, yG, false);
      ECParameterSpec var2 = new ECParameterSpec(var0, var1, n);
      return var2;
   }

   public static ECParameterSpec getSM2NamedCuve() {
      ECCurve.Fp var0 = new ECCurve.Fp(p, a, b);
      ECPoint var1 = var0.createPoint(xG, yG, false);
      return new ECNamedCurveParameterSpec(OID_SM2_256CURVE, var0, var1, n);
   }

   public static java.security.spec.ECParameterSpec getStandardECParamSpec() {
      EllipticCurve var0 = new EllipticCurve(new ECFieldFp(p), a, b);
      java.security.spec.ECPoint var1 = new java.security.spec.ECPoint(xG, yG);
      java.security.spec.ECParameterSpec var2 = new java.security.spec.ECParameterSpec(var0, var1, n, 1);
      return var2;
   }

   public static java.security.spec.ECParameterSpec getStandardECParamSpec_f2m() {
      EllipticCurve var0 = new EllipticCurve(new ECFieldF2m(m, new int[]{k}), a, b);
      java.security.spec.ECPoint var1 = new java.security.spec.ECPoint(xG, yG);
      java.security.spec.ECParameterSpec var2 = new java.security.spec.ECParameterSpec(var0, var1, n, 1);
      return var2;
   }

   public static byte[] intToBytes(BigInteger var0, int var1) {
      if (var1 == 0) {
         return intToBytes(var0);
      } else {
         int var2 = var1 / 8;
         var2 = var1 % 8 == 0 ? var2 : var2 + 1;
         byte[] var3 = intToBytes(var0);
         if (var3.length == var2) {
            return var3;
         } else {
            int var4 = var2 - var3.length;
            byte[] var5 = new byte[var2];
            System.arraycopy(var3, 0, var5, var4, var3.length);
            return var5;
         }
      }
   }

   public static byte[] intToBytes(BigInteger var0) {
      byte[] var1 = var0.toByteArray();
      byte[] var2;
      if (var1.length < 32) {
         var2 = new byte[32];
         System.arraycopy(var1, 0, var2, 32 - var1.length, var1.length);
         var1 = var2;
      } else if (var1.length > 32) {
         var2 = new byte[var1.length - (var1.length - 32)];
         System.arraycopy(var1, var1.length - 32, var2, 0, var2.length);
         var1 = var2;
      }

      return var1;
   }
}
