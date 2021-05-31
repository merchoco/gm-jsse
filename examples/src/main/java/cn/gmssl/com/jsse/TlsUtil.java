package cn.gmssl.com.jsse;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class TlsUtil {
   private static final byte[] B0 = new byte[0];
   public static final byte[] LABEL_MASTER_SECRET = new byte[]{109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};
   static final byte[] LABEL_KEY_EXPANSION = new byte[]{107, 101, 121, 32, 101, 120, 112, 97, 110, 115, 105, 111, 110};
   static final byte[] LABEL_CLIENT_WRITE_KEY = new byte[]{99, 108, 105, 101, 110, 116, 32, 119, 114, 105, 116, 101, 32, 107, 101, 121};
   static final byte[] LABEL_SERVER_WRITE_KEY = new byte[]{115, 101, 114, 118, 101, 114, 32, 119, 114, 105, 116, 101, 32, 107, 101, 121};
   static final byte[] LABEL_IV_BLOCK = new byte[]{73, 86, 32, 98, 108, 111, 99, 107};
   private static final byte[] HMAC_ipad64 = genPad((byte)54, 64);
   private static final byte[] HMAC_ipad128 = genPad((byte)54, 128);
   private static final byte[] HMAC_opad64 = genPad((byte)92, 64);
   private static final byte[] HMAC_opad128 = genPad((byte)92, 128);

   static byte[] genPad(byte var0, int var1) {
      byte[] var2 = new byte[var1];
      Arrays.fill(var2, var0);
      return var2;
   }

   static byte[] concat(byte[] var0, byte[] var1) {
      int var2 = var0.length;
      int var3 = var1.length;
      byte[] var4 = new byte[var2 + var3];
      System.arraycopy(var0, 0, var4, 0, var2);
      System.arraycopy(var1, 0, var4, var2, var3);
      return var4;
   }

   static byte[] doGBTLS10PRF(byte[] var0, byte[] var1, byte[] var2, int var3) throws NoSuchAlgorithmException, DigestException {
      MessageDigest var4 = MessageDigest.getInstance("SHA1");
      MessageDigest var5 = MessageDigest.getInstance("SM3");
      return doTLS10PRF(var0, var1, var2, var3, var4, var5);
   }

   static byte[] doTLS10PRF(byte[] var0, byte[] var1, byte[] var2, int var3, MessageDigest var4, MessageDigest var5) throws DigestException {
      if (var0 == null) {
         var0 = B0;
      }

      int var6 = var0.length >> 1;
      int var7 = var6 + (var0.length & 1);
      byte[] var8 = new byte[var3];
      expand(var4, 20, var0, 0, var7, var1, var2, var8, (byte[])HMAC_ipad64.clone(), (byte[])HMAC_opad64.clone());
      expand(var5, 32, var0, var6, var7, var1, var2, var8, (byte[])HMAC_ipad64.clone(), (byte[])HMAC_opad64.clone());
      return var8;
   }

   static byte[] doGBTLS11PRF(byte[] var0, byte[] var1, byte[] var2, int var3) throws NoSuchAlgorithmException, DigestException {
      MessageDigest var4 = MessageDigest.getInstance("SM3");
      return doTLS11PRF(var0, var1, var2, var3, var4);
   }

   static byte[] doTLS11PRF(byte[] var0, byte[] var1, byte[] var2, int var3, MessageDigest var4) throws DigestException {
      if (var0 == null) {
         var0 = B0;
      }

      byte[] var5 = new byte[var3];
      expand(var4, 32, var0, 0, var0.length, var1, var2, var5, (byte[])HMAC_ipad64.clone(), (byte[])HMAC_opad64.clone());
      return var5;
   }

   private static void expand(MessageDigest var0, int var1, byte[] var2, int var3, int var4, byte[] var5, byte[] var6, byte[] var7, byte[] var8, byte[] var9) throws DigestException {
      for(int var10 = 0; var10 < var4; ++var10) {
         var8[var10] ^= var2[var10 + var3];
         var9[var10] ^= var2[var10 + var3];
      }

      byte[] var16 = new byte[var1];
      byte[] var11 = null;
      int var12 = var7.length;

      int var14;
      for(int var13 = 0; var12 > 0; var12 -= var14) {
         var0.update(var8);
         if (var11 == null) {
            var0.update(var5);
            var0.update(var6);
         } else {
            var0.update(var11);
         }

         var0.digest(var16, 0, var1);
         var0.update(var9);
         var0.update(var16);
         if (var11 == null) {
            var11 = new byte[var1];
         }

         var0.digest(var11, 0, var1);
         var0.update(var8);
         var0.update(var11);
         var0.update(var5);
         var0.update(var6);
         var0.digest(var16, 0, var1);
         var0.update(var9);
         var0.update(var16);
         var0.digest(var16, 0, var1);
         var14 = Math.min(var1, var12);

         for(int var15 = 0; var15 < var14; ++var15) {
            int var10001 = var13++;
            var7[var10001] ^= var16[var15];
         }
      }

   }

   public static int[] signatrueAndHash(String var0) {
      byte var1 = 0;
      byte var2 = 0;
      if (var0.contains("SHA")) {
         var1 = 2;
      } else if (var0.contains("SM3")) {
         var1 = 7;
      }

      if (var0.contains("RSA")) {
         var2 = 1;
      } else if (var0.contains("ECDHE")) {
         var2 = 4;
      }

      return new int[]{var1, var2};
   }

   public static void debug(String var0, byte[] var1) {
      System.out.println(var0 + ":" + HexBin.encode(var1));
   }
}
