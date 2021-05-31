package cn.gmssl.crypto.impl.sm2;

import cn.gmssl.crypto.impl.SM3;
import cn.gmssl.crypto.util.Debug;
import cn.gmssl.crypto.util.PrintUtil;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;
import org.bc.crypto.engines.MyBigInteger;
import org.bc.jce.interfaces.ECPrivateKey;
import org.bc.jce.interfaces.ECPublicKey;
import org.bc.jce.spec.ECParameterSpec;
import org.bc.math.ec.ECPoint;

public class SM2Encryption {
   public static byte[] encrypt_der(ECPublicKey var0, byte[] var1, SecureRandom var2) throws Exception {
      if (var2 == null) {
         var2 = SecureRandom.getInstance("SHA1PRNG");
      }

      if (Debug.DEBUG) {
         System.out.println("SM2: debug yes");
      }

      if (Debug.sm2_encryption || Debug.DEBUG) {
         PrintUtil.printHex(var0.getQ().getX().toBigInteger(), "SM2: public:x");
         PrintUtil.printHex(var0.getQ().getY().toBigInteger(), "SM2: public:y");
         PrintUtil.printHex(var1, "SM2: plaintext");
      }

      ECParameterSpec var3 = var0.getParameters();
      BigInteger var4 = var3.getN();
      ECPoint var5 = var3.getG();
      BigInteger var6 = var3.getH();
      Object var7 = null;
      Object var8 = null;
      BigInteger var9 = null;
      BigInteger var10 = null;
      Object var11 = null;

      byte[] var22;
      byte[] var23;
      byte[] var24;
      do {
         BigInteger var12 = MyBigInteger.gen(var4, var2);
         ECPoint var13 = var5.multiply(var12);
         var9 = var13.getX().toBigInteger();
         var10 = var13.getY().toBigInteger();
         ECPoint var14 = var0.getQ();
         ECPoint var15 = var14.multiply(var6);
         if (var15.isInfinity()) {
            throw new Exception("encrypt error");
         }

         ECPoint var16 = var14.multiply(var12);
         BigInteger var17 = var16.getX().toBigInteger();
         BigInteger var18 = var16.getY().toBigInteger();
         if (Debug.sm2_encryption || Debug.DEBUG) {
            PrintUtil.printHex(var17, "SM2: x2");
            PrintUtil.printHex(var18, "SM2: y2");
         }

         var22 = SM2Util.intToBytes(var17);
         var23 = SM2Util.intToBytes(var18);
         ByteArrayOutputStream var19 = new ByteArrayOutputStream();
         var19.write(var22);
         var19.write(var23);
         int var20 = var1.length * 8;
         byte[] var21 = var19.toByteArray();
         var24 = SM2KeyExchangeUtil.KDF(var21, var20);
         if (Debug.sm2_encryption || Debug.DEBUG) {
            PrintUtil.printHex(var24, "SM2: t");
         }
      } while(repeat(var24));

      byte[] var25 = new byte[var1.length];

      for(int var26 = 0; var26 < var1.length; ++var26) {
         var25[var26] = (byte)(var1[var26] ^ var24[var26]);
      }

      SM3 var27 = new SM3();
      byte[] var28 = new byte[var27.getDigestSize()];
      var27.update(var22, 0, var22.length);
      var27.update(var1, 0, var1.length);
      var27.update(var23, 0, var23.length);
      var27.doFinal(var28, 0);
      if (Debug.sm2_encryption || Debug.DEBUG) {
         PrintUtil.printHex(var9, "SM2: x1");
         PrintUtil.printHex(var10, "SM2: y1");
         PrintUtil.printHex(var25, "SM2: C2");
         PrintUtil.printHex(var28, "SM2: C3");
      }

      DERSequence var29 = new DERSequence(new ASN1Encodable[]{new ASN1Integer(var9), new ASN1Integer(var10), new DEROctetString(var28), new DEROctetString(var25)});
      return var29.getEncoded();
   }

   public static byte[] decrypt_der(ECPrivateKey var0, byte[] var1) throws Exception {
      if (Debug.sm2_encryption) {
         PrintUtil.printHex(var0.getD(), "private:d");
         PrintUtil.printHex(var1, "cipherText");
      }

      ASN1Sequence var2 = ASN1Sequence.getInstance(var1);
      ECParameterSpec var3 = var0.getParameters();
      BigInteger var4 = var3.getH();
      BigInteger var5 = var0.getD();
      SM3 var6 = new SM3();
      BigInteger var7 = ((ASN1Integer)var2.getObjectAt(0)).getPositiveValue();
      BigInteger var8 = ((ASN1Integer)var2.getObjectAt(1)).getPositiveValue();
      byte[] var9 = ((ASN1OctetString)var2.getObjectAt(3)).getOctets();
      byte[] var10 = ((ASN1OctetString)var2.getObjectAt(2)).getOctets();
      if (Debug.sm2_encryption) {
         PrintUtil.printHex(var7, "x1");
         PrintUtil.printHex(var8, "y1");
         PrintUtil.printHex(var9, "C2");
         PrintUtil.printHex(var10, "C3");
      }

      ECPoint var11 = var3.getCurve().createPoint(var7, var8, false);
      if (Debug.sm2_encryption) {
         PrintUtil.printHex(var11.getX().toBigInteger().toByteArray(), "C1_x");
         PrintUtil.printHex(var11.getY().toBigInteger().toByteArray(), "C1_y");
      }

      ECPoint var12 = var11.multiply(var5);
      if (Debug.sm2_encryption) {
         PrintUtil.printHex(var12.getX().toBigInteger().toByteArray(), "Temp_x");
         PrintUtil.printHex(var12.getY().toBigInteger().toByteArray(), "Temp_y");
      }

      BigInteger var13 = var12.getX().toBigInteger();
      BigInteger var14 = var12.getY().toBigInteger();
      byte[] var15 = SM2Util.intToBytes(var13);
      byte[] var16 = SM2Util.intToBytes(var14);
      ByteArrayOutputStream var17 = new ByteArrayOutputStream();
      var17.write(var15);
      var17.write(var16);
      byte[] var18 = var17.toByteArray();
      byte[] var19 = SM2KeyExchangeUtil.KDF(var18, var9.length * 8);
      if (repeat(var19)) {
         throw new RuntimeException("error cipher text(02)");
      } else {
         byte[] var20 = new byte[var9.length];

         for(int var21 = 0; var21 < var20.length; ++var21) {
            var20[var21] = (byte)(var9[var21] ^ var19[var21]);
         }

         var6.update(var15, 0, var15.length);
         var6.update(var20, 0, var20.length);
         var6.update(var16, 0, var16.length);
         byte[] var23 = new byte[var6.getDigestSize()];
         var6.doFinal(var23, 0);
         boolean var22 = Arrays.equals(var23, var10);
         if (Debug.sm2_encryption) {
            PrintUtil.printHex(var15, "x2Bytes");
            PrintUtil.printHex(var16, "y2Bytes");
            PrintUtil.printHex(var23, "t");
            PrintUtil.printHex(var20, "M");
            PrintUtil.printHex(var23, "u");
         }

         if (!var22) {
            throw new RuntimeException("error cipher text(03)");
         } else {
            return var20;
         }
      }
   }

   public static boolean repeat(byte[] var0) {
      boolean var1 = true;
      byte[] var5 = var0;
      int var4 = var0.length;

      for(int var3 = 0; var3 < var4; ++var3) {
         byte var2 = var5[var3];
         var1 = var1 && var2 == 0;
         if (!var1) {
            break;
         }
      }

      return var1;
   }
}
