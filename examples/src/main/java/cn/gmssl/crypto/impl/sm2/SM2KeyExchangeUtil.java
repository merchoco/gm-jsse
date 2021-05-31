package cn.gmssl.crypto.impl.sm2;

import cn.gmssl.crypto.impl.SM3;
import cn.gmssl.crypto.util.Debug;
import cn.gmssl.crypto.util.PrintUtil;
import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.Digest;
import org.bc.crypto.engines.MyBigInteger;
import org.bc.jce.interfaces.ECPrivateKey;
import org.bc.jce.interfaces.ECPublicKey;
import org.bc.math.ec.ECPoint;

public class SM2KeyExchangeUtil {
   public static BigInteger generateRandom(ECPublicKey var0, SecureRandom var1) {
      BigInteger var2 = var0.getParameters().getN();
      return generateRandom(var2, var1);
   }

   public static BigInteger generateRandom(BigInteger var0, SecureRandom var1) {
      BigInteger var2 = MyBigInteger.gen(var0, var1);
      return var2;
   }

   public static ECPoint generateR(ECPublicKey var0, BigInteger var1) {
      ECPoint var2 = var0.getParameters().getG();
      ECPoint var3 = var2.multiply(var1);
      return var3;
   }

   public static byte[] generateK(ECPublicKey var0, ECPrivateKey var1, ECPublicKey var2, BigInteger var3, ECPoint var4, byte[] var5, byte[] var6, boolean var7, int var8) throws Exception {
      ECPoint var9 = generateR(var0, var3);
      return caculateK(var0, var1, var2, var9, var4, var3, var5, var6, var7, var8);
   }

   public static byte[] caculateK(ECPublicKey var0, ECPrivateKey var1, ECPublicKey var2, ECPoint var3, ECPoint var4, BigInteger var5, byte[] var6, byte[] var7, boolean var8, int var9) throws Exception {
      if (Debug.sm2_key_exchange) {
         System.out.println("caculateK-publicKey:" + var0);
         System.out.println("caculateK-privateKey:" + var1);
         System.out.println("caculateK-publicKeyRemote:" + var2);
         PrintUtil.printHex(var3.getX().toBigInteger(), "caculateK-RLocal.X");
         PrintUtil.printHex(var3.getY().toBigInteger(), "caculateK-RLocal.Y");
         PrintUtil.printHex(var4.getX().toBigInteger(), "caculateK-RRemote.X");
         PrintUtil.printHex(var4.getY().toBigInteger(), "caculateK-RRemote.Y");
         PrintUtil.printHex(var5, "caculateK-randomLocal");
         PrintUtil.printHex(var6, "caculateK-idLocal");
         PrintUtil.printHex(var7, "caculateK-idRemote");
         System.out.println("caculateK-active:" + var8);
      }

      BigInteger var10 = var0.getParameters().getN();
      int var11 = (int)(Math.ceil((double)(var10.subtract(BigInteger.ONE).bitLength() / 2)) - 1.0D);
      BigInteger var12 = BigInteger.ONE.shiftLeft(var11);
      BigInteger var13 = var3.getX().toBigInteger();
      var13 = var12.add(var13.and(var12.subtract(BigInteger.ONE)));
      BigInteger var14 = var1.getD();
      BigInteger var15 = var14.add(var13.multiply(var5)).mod(var10);
      BigInteger var16 = var4.getX().toBigInteger();
      var16 = var12.add(var16.and(var12.subtract(BigInteger.ONE)));
      BigInteger var17 = var0.getParameters().getH();
      ECPoint var18 = var2.getQ();
      ECPoint var19 = var18.add(var4.multiply(var16)).multiply(var17.multiply(var15));
      BigInteger var20 = var19.getX().toBigInteger();
      BigInteger var21 = var19.getY().toBigInteger();
      SM3 var22 = new SM3();
      byte[] var23 = SM2Util.Z(var6, (ECPublicKey)var0, (Digest)var22);
      byte[] var24 = SM2Util.Z(var7, (ECPublicKey)var2, (Digest)var22);
      ByteArrayOutputStream var25 = new ByteArrayOutputStream();

      try {
         var25.write(SM2Util.intToBytes(var20));
         var25.write(SM2Util.intToBytes(var21));
         if (var8) {
            var25.write(var23);
            var25.write(var24);
         } else {
            var25.write(var24);
            var25.write(var23);
         }
      } catch (Exception var28) {
         throw var28;
      }

      if (Debug.sm2_key_exchange) {
         PrintUtil.printHex(var13, "caculateK-x");
         PrintUtil.printHex(var15, "caculateK-t");
         PrintUtil.printHex(var16, "caculateK-x2");
         PrintUtil.printHex(var20, "caculateK-xU");
         PrintUtil.printHex(var21, "caculateK-yU");
         PrintUtil.printHex(var23, "caculateK-ZLocal");
         PrintUtil.printHex(var24, "caculateK-ZRemote");
      }

      byte[] var26 = var25.toByteArray();
      byte[] var27 = KDF(var26, var9 * 8);
      return var27;
   }

   public static byte[] caculateK_debug(ECPublicKey var0, ECPrivateKey var1, ECPublicKey var2, ECPoint var3, ECPoint var4, BigInteger var5, byte[] var6, byte[] var7, boolean var8, StringBuilder var9) throws Exception {
      if (Debug.sm2_key_exchange) {
         System.out.println("caculateK-publicKey:" + var0);
         System.out.println("caculateK-privateKey:" + var1);
         System.out.println("caculateK-publicKeyRemote:" + var2);
         PrintUtil.printHex(var3.getX().toBigInteger(), "caculateK-RLocal.X");
         PrintUtil.printHex(var3.getY().toBigInteger(), "caculateK-RLocal.Y");
         PrintUtil.printHex(var4.getX().toBigInteger(), "caculateK-RRemote.X");
         PrintUtil.printHex(var4.getY().toBigInteger(), "caculateK-RRemote.Y");
         PrintUtil.printHex(var5, "caculateK-randomLocal");
         PrintUtil.printHex(var6, "caculateK-idLocal");
         PrintUtil.printHex(var7, "caculateK-idRemote");
         System.out.println("caculateK-active:" + var8);
      }

      BigInteger var10 = var0.getParameters().getN();
      int var11 = (int)(Math.ceil((double)(var10.subtract(BigInteger.ONE).bitLength() / 2)) - 1.0D);
      BigInteger var12 = BigInteger.ONE.shiftLeft(var11);
      BigInteger var13 = var3.getX().toBigInteger();
      var13 = var12.add(var13.and(var12.subtract(BigInteger.ONE)));
      BigInteger var14 = var1.getD();
      BigInteger var15 = var14.add(var13.multiply(var5)).mod(var10);
      BigInteger var16 = var4.getX().toBigInteger();
      var16 = var12.add(var16.and(var12.subtract(BigInteger.ONE)));
      BigInteger var17 = var0.getParameters().getH();
      ECPoint var18 = var2.getQ();
      ECPoint var19 = var18.add(var4.multiply(var16)).multiply(var17.multiply(var15));
      BigInteger var20 = var19.getX().toBigInteger();
      BigInteger var21 = var19.getY().toBigInteger();
      SM3 var22 = new SM3();
      byte[] var23 = SM2Util.Z(var6, (ECPublicKey)var0, (Digest)var22);
      byte[] var24 = SM2Util.Z(var7, (ECPublicKey)var2, (Digest)var22);
      ByteArrayOutputStream var25 = new ByteArrayOutputStream();

      try {
         var25.write(SM2Util.intToBytes(var20));
         var25.write(SM2Util.intToBytes(var21));
         if (var8) {
            var25.write(var23);
            var25.write(var24);
         } else {
            var25.write(var24);
            var25.write(var23);
         }
      } catch (Exception var28) {
         throw var28;
      }

      if (Debug.sm2_key_exchange) {
         PrintUtil.printHex(var13, "caculateK-x");
         PrintUtil.printHex(var15, "caculateK-t");
         PrintUtil.printHex(var16, "caculateK-x2");
         PrintUtil.printHex(var20, "caculateK-xU");
         PrintUtil.printHex(var21, "caculateK-yU");
         PrintUtil.printHex(var23, "caculateK-ZLocal");
         PrintUtil.printHex(var24, "caculateK-ZRemote");
      }

      byte[] var26 = var25.toByteArray();
      byte[] var27 = KDF(var26, 384);
      var9.append("caculateK-publicKey:" + var0 + "\n");
      var9.append("caculateK-privateKey:" + var1 + "\n");
      var9.append("caculateK-publicKeyRemote:" + var2 + "\n");
      var9.append("caculateK-RLocal.X:" + var3.getX().toBigInteger().toString(16) + "\n");
      var9.append("caculateK-RLocal.Y:" + var3.getY().toBigInteger().toString(16) + "\n");
      var9.append("caculateK-RRemote.X:" + var4.getX().toBigInteger().toString(16) + "\n");
      var9.append("caculateK-RRemote.Y:" + var4.getY().toBigInteger().toString(16) + "\n");
      var9.append("caculateK-randomLocal" + var5.toString(16) + "\n");
      var9.append("caculateK-idLocal:" + HexBin.encode(var6) + "\n");
      var9.append("caculateK-x:" + var13.toString(16) + "\n");
      var9.append("caculateK-t:" + var15.toString(16) + "\n");
      var9.append("caculateK-x2:" + var16.toString(16) + "\n");
      var9.append("caculateK-xU-bytes:" + HexBin.encode(SM2Util.intToBytes(var20)) + "\n");
      var9.append("caculateK-xU-length:" + SM2Util.intToBytes(var20).length + "\n");
      var9.append("caculateK-yU-bytes:" + HexBin.encode(SM2Util.intToBytes(var21)) + "\n");
      var9.append("caculateK-yU-length:" + SM2Util.intToBytes(var21).length + "\n");
      var9.append("caculateK-ZLocal:" + HexBin.encode(var23) + "\n");
      var9.append("caculateK-ZRemote:" + HexBin.encode(var24) + "\n");
      var9.append("caculateK-K:" + var27 + "\n");
      return var27;
   }

   public static byte[] KDF(byte[] var0, int var1) {
      if (Debug.sm2 || Debug.sm2_key_exchange) {
         PrintUtil.printHex(var0, "KDF-Z");
         System.out.println("KDF-kLen:" + var1);
      }

      SM3 var2 = new SM3();
      int var3 = var2.getDigestSize() * 8;
      int var4 = var1 / 8;
      byte[] var5 = new byte[var4];
      int var6 = 0;

      int var7;
      for(var7 = 1; var6 < var1 / var3; ++var7) {
         var2.update(var0, 0, var0.length);
         var2.update((byte)(var7 >> 24 & 255));
         var2.update((byte)(var7 >> 16 & 255));
         var2.update((byte)(var7 >> 8 & 255));
         var2.update((byte)(var7 >> 0 & 255));
         var2.doFinal(var5, var6 * var3 / 8);
         ++var6;
      }

      if (var1 % var3 != 0) {
         byte[] var8 = new byte[var2.getDigestSize()];
         var2.update(var0, 0, var0.length);
         var2.update((byte)(var7 >> 24 & 255));
         var2.update((byte)(var7 >> 16 & 255));
         var2.update((byte)(var7 >> 8 & 255));
         var2.update((byte)(var7 >> 0 & 255));
         var2.doFinal(var8, 0);
         int var9 = var6 * var3 / 8;
         System.arraycopy(var8, 0, var5, var9, var1 / 8 - var9);
      }

      if (Debug.sm2 || Debug.sm2_key_exchange) {
         PrintUtil.printHex(var5, "KDF-K");
      }

      return var5;
   }
}
