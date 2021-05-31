package cn.gmssl.crypto.impl.sm2;

import cn.gmssl.crypto.impl.SM3;
import cn.gmssl.crypto.util.Debug;
import cn.gmssl.crypto.util.PrintUtil;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import org.bc.crypto.Digest;
import org.bc.jce.interfaces.ECPrivateKey;
import org.bc.jce.interfaces.ECPublicKey;
import org.bc.jce.spec.ECParameterSpec;
import org.bc.math.ec.ECCurve;
import org.bc.math.ec.ECPoint;

public class SM2Util {
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

   public static byte[] Z(byte[] var0, ECPublicKey var1, Digest var2) {
      if (var0 == null) {
         var0 = "1234567812345678".getBytes();
      }

      int var3 = var0.length * 8;
      ECCurve var4 = var1.getParameters().getCurve();
      BigInteger var5 = var4.getA().toBigInteger();
      BigInteger var6 = var4.getB().toBigInteger();
      ECPoint var7 = var1.getParameters().getG();
      BigInteger var8 = var7.getX().toBigInteger();
      BigInteger var9 = var7.getY().toBigInteger();
      ECPoint var10 = var1.getQ();
      BigInteger var11 = var10.getX().toBigInteger();
      BigInteger var12 = var10.getY().toBigInteger();
      byte[] var13 = new byte[]{(byte)(var3 >> 8), (byte)var3};
      int var14 = 0;
      if (var4 instanceof ECCurve.F2m) {
         var14 = ((ECCurve.F2m)var4).getM();
      }

      byte[] var15 = intToBytes(var5, var14);
      byte[] var16 = intToBytes(var6, var14);
      byte[] var17 = intToBytes(var8, var14);
      byte[] var18 = intToBytes(var9, var14);
      byte[] var19 = intToBytes(var11, var14);
      byte[] var20 = intToBytes(var12, var14);
      SM3 var21 = new SM3();
      var21.update(var13, 0, var13.length);
      var21.update(var0, 0, var0.length);
      var21.update(var15, 0, var15.length);
      var21.update(var16, 0, var16.length);
      var21.update(var17, 0, var17.length);
      var21.update(var18, 0, var18.length);
      var21.update(var19, 0, var19.length);
      var21.update(var20, 0, var20.length);
      byte[] var22 = new byte[var21.getDigestSize()];
      var21.doFinal(var22, 0);
      if (Debug.sm2 || Debug.sm2_key_exchange) {
         PrintUtil.printHex(var22, "Z()");
         System.out.println("Z end");
      }

      var2.update(var22, 0, var22.length);
      return var22;
   }

   public static byte[] Z(byte[] var0, ECPublicKey var1, MessageDigest var2) throws Exception {
      if (var0 == null) {
         var0 = "1234567812345678".getBytes();
      }

      int var3 = var0.length * 8;
      ECCurve var4 = var1.getParameters().getCurve();
      BigInteger var5 = var4.getA().toBigInteger();
      BigInteger var6 = var4.getB().toBigInteger();
      ECPoint var7 = var1.getParameters().getG();
      BigInteger var8 = var7.getX().toBigInteger();
      BigInteger var9 = var7.getY().toBigInteger();
      ECPoint var10 = var1.getQ();
      BigInteger var11 = var10.getX().toBigInteger();
      BigInteger var12 = var10.getY().toBigInteger();
      byte[] var13 = new byte[]{(byte)(var3 >> 8), (byte)var3};
      int var14 = 0;
      if (var4 instanceof ECCurve.F2m) {
         var14 = ((ECCurve.F2m)var4).getM();
      }

      byte[] var15 = intToBytes(var5, var14);
      byte[] var16 = intToBytes(var6, var14);
      byte[] var17 = intToBytes(var8, var14);
      byte[] var18 = intToBytes(var9, var14);
      byte[] var19 = intToBytes(var11, var14);
      byte[] var20 = intToBytes(var12, var14);
      MessageDigest var21 = MessageDigest.getInstance("SM3");
      var21.update(var13, 0, var13.length);
      var21.update(var0, 0, var0.length);
      var21.update(var15, 0, var15.length);
      var21.update(var16, 0, var16.length);
      var21.update(var17, 0, var17.length);
      var21.update(var18, 0, var18.length);
      var21.update(var19, 0, var19.length);
      var21.update(var20, 0, var20.length);
      byte[] var22 = var21.digest();
      var2.update(var22);
      return var22;
   }

   public static byte[] Z(byte[] var0, java.security.interfaces.ECPublicKey var1, MessageDigest var2) throws Exception {
      if (var0 == null) {
         var0 = "1234567812345678".getBytes();
      }

      int var3 = var0.length * 8;
      EllipticCurve var4 = var1.getParams().getCurve();
      BigInteger var5 = var4.getA();
      BigInteger var6 = var4.getB();
      java.security.spec.ECPoint var7 = var1.getParams().getGenerator();
      BigInteger var8 = var7.getAffineX();
      BigInteger var9 = var7.getAffineY();
      java.security.spec.ECPoint var10 = var1.getW();
      BigInteger var11 = var10.getAffineX();
      BigInteger var12 = var10.getAffineY();
      byte[] var13 = new byte[]{(byte)(var3 >> 8), (byte)var3};
      byte var14 = 0;
      byte[] var15 = intToBytes(var5, var14);
      byte[] var16 = intToBytes(var6, var14);
      byte[] var17 = intToBytes(var8, var14);
      byte[] var18 = intToBytes(var9, var14);
      byte[] var19 = intToBytes(var11, var14);
      byte[] var20 = intToBytes(var12, var14);
      MessageDigest var21 = MessageDigest.getInstance("SM3");
      var21.update(var13, 0, var13.length);
      var21.update(var0, 0, var0.length);
      var21.update(var15, 0, var15.length);
      var21.update(var16, 0, var16.length);
      var21.update(var17, 0, var17.length);
      var21.update(var18, 0, var18.length);
      var21.update(var19, 0, var19.length);
      var21.update(var20, 0, var20.length);
      byte[] var22 = var21.digest();
      var2.update(var22);
      return var22;
   }

   public static ECParameterSpec getSM2ParamSpec() {
      ECCurve.Fp var0 = new ECCurve.Fp(p, a, b);
      ECPoint var1 = var0.createPoint(xG, yG, false);
      ECParameterSpec var2 = new ECParameterSpec(var0, var1, n);
      return var2;
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

   public static byte[] encodePoint(ECPoint var0) {
      BigInteger var1 = var0.getX().toBigInteger();
      BigInteger var2 = var0.getY().toBigInteger();
      StdDSAEncoder var3 = new StdDSAEncoder();
      Object var4 = null;

      try {
         byte[] var7 = var3.encode(var1, var2);
         return var7;
      } catch (IOException var6) {
         throw new RuntimeException(var6);
      }
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
         PrintUtil.printHex(var1, "SM2: array1");
         var2 = new byte[32];
         System.arraycopy(var1, 0, var2, 32 - var1.length, var1.length);
         var1 = var2;
         PrintUtil.printHex(var2, "SM2: array2");
      } else if (var1.length > 32) {
         PrintUtil.printHex(var1, "SM2: array3");
         var2 = new byte[var1.length - (var1.length - 32)];
         System.arraycopy(var1, var1.length - 32, var2, 0, var2.length);
         var1 = var2;
         PrintUtil.printHex(var2, "SM2: array4");
      }

      return var1;
   }

   public static byte[] getId(X509Certificate var0, int var1) {
      try {
         return "1234567812345678".getBytes();
      } catch (Exception var3) {
         throw new RuntimeException(var3);
      }
   }

   public static Signature sm2Sign(PrivateKey var0, PublicKey var1) {
      try {
         Signature var2 = Signature.getInstance("SM3withSM2");
         String var3;
         switch((var3 = var2.getProvider().getName()).hashCode()) {
         case 67937158:
            if (var3.equals("GMJCE")) {
               var2.setParameter(new SM2ParameterSpec("1234567812345678".getBytes(), var1));
            }
         default:
            var2.initSign(var0);
            return var2;
         }
      } catch (Exception var4) {
         throw new RuntimeException(var4);
      }
   }

   public static ECPublicKey toTsgECPublicKey(PublicKey var0) throws Exception {
      if (!(var0 instanceof java.security.interfaces.ECPublicKey)) {
         return (ECPublicKey)var0;
      } else {
         java.security.interfaces.ECPublicKey var1 = (java.security.interfaces.ECPublicKey)var0;
         java.security.spec.ECParameterSpec var2 = getStandardECParamSpec();
         ECPublicKeySpec var3 = new ECPublicKeySpec(var1.getW(), var2);
         KeyFactory var4 = KeyFactory.getInstance("SM2", "GMJCE");
         PublicKey var5 = var4.generatePublic(var3);
         return (ECPublicKey)var5;
      }
   }

   public static ECPrivateKey toTsgECPrivateKey(PrivateKey var0) throws Exception {
      if (!(var0 instanceof java.security.interfaces.ECPrivateKey)) {
         return (ECPrivateKey)var0;
      } else {
         java.security.interfaces.ECPrivateKey var1 = (java.security.interfaces.ECPrivateKey)var0;
         java.security.spec.ECParameterSpec var2 = getStandardECParamSpec();
         ECPrivateKeySpec var3 = new ECPrivateKeySpec(var1.getS(), var2);
         KeyFactory var4 = KeyFactory.getInstance("SM2", "GMJCE");
         PrivateKey var5 = var4.generatePrivate(var3);
         return (ECPrivateKey)var5;
      }
   }
}
