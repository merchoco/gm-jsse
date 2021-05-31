package cn.gmssl.com.sun.crypto.provider;

import cn.gmssl.sun.security.internal.spec.TlsPrfParameterSpec;
import java.io.UnsupportedEncodingException;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

abstract class TlsPrfGenerator extends KeyGeneratorSpi {
   private static final byte[] B0 = new byte[0];
   static final byte[] LABEL_MASTER_SECRET = new byte[]{109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};
   static final byte[] LABEL_KEY_EXPANSION = new byte[]{107, 101, 121, 32, 101, 120, 112, 97, 110, 115, 105, 111, 110};
   static final byte[] LABEL_CLIENT_WRITE_KEY = new byte[]{99, 108, 105, 101, 110, 116, 32, 119, 114, 105, 116, 101, 32, 107, 101, 121};
   static final byte[] LABEL_SERVER_WRITE_KEY = new byte[]{115, 101, 114, 118, 101, 114, 32, 119, 114, 105, 116, 101, 32, 107, 101, 121};
   static final byte[] LABEL_IV_BLOCK = new byte[]{73, 86, 32, 98, 108, 111, 99, 107};
   private static final byte[] HMAC_ipad64 = genPad((byte)54, 64);
   private static final byte[] HMAC_ipad128 = genPad((byte)54, 128);
   private static final byte[] HMAC_opad64 = genPad((byte)92, 64);
   private static final byte[] HMAC_opad128 = genPad((byte)92, 128);
   static final byte[][] SSL3_CONST = genConst();
   private static final String MSG = "TlsPrfGenerator must be initialized using a TlsPrfParameterSpec";
   private TlsPrfParameterSpec spec;

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

   private static byte[][] genConst() {
      byte var0 = 10;
      byte[][] var1 = new byte[var0][];

      for(int var2 = 0; var2 < var0; ++var2) {
         byte[] var3 = new byte[var2 + 1];
         Arrays.fill(var3, (byte)(65 + var2));
         var1[var2] = var3;
      }

      return var1;
   }

   protected void engineInit(SecureRandom var1) {
      throw new InvalidParameterException("TlsPrfGenerator must be initialized using a TlsPrfParameterSpec");
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      if (!(var1 instanceof TlsPrfParameterSpec)) {
         throw new InvalidAlgorithmParameterException("TlsPrfGenerator must be initialized using a TlsPrfParameterSpec");
      } else {
         this.spec = (TlsPrfParameterSpec)var1;
         SecretKey var3 = this.spec.getSecret();
         if (var3 != null && !"RAW".equals(var3.getFormat())) {
            throw new InvalidAlgorithmParameterException("Key encoding format must be RAW");
         }
      }
   }

   protected void engineInit(int var1, SecureRandom var2) {
      throw new InvalidParameterException("TlsPrfGenerator must be initialized using a TlsPrfParameterSpec");
   }

   SecretKey engineGenerateKey0(boolean var1) {
      if (this.spec == null) {
         throw new IllegalStateException("TlsPrfGenerator must be initialized");
      } else {
         SecretKey var2 = this.spec.getSecret();
         byte[] var3 = var2 == null ? null : var2.getEncoded();

         try {
            byte[] var4 = this.spec.getLabel().getBytes("UTF8");
            int var5 = this.spec.getOutputLength();
            byte[] var6 = var1 ? doTLS12PRF(var3, var4, this.spec.getSeed(), var5, this.spec.getPRFHashAlg(), this.spec.getPRFHashLength(), this.spec.getPRFBlockSize()) : doTLS10PRF(var3, var4, this.spec.getSeed(), var5);
            return new SecretKeySpec(var6, "TlsPrf");
         } catch (GeneralSecurityException var7) {
            throw new ProviderException("Could not generate PRF", var7);
         } catch (UnsupportedEncodingException var8) {
            throw new ProviderException("Could not generate PRF", var8);
         }
      }
   }

   static byte[] doTLS12PRF(byte[] var0, byte[] var1, byte[] var2, int var3, String var4, int var5, int var6) throws NoSuchAlgorithmException, DigestException {
      if (var4 == null) {
         throw new NoSuchAlgorithmException("Unspecified PRF algorithm");
      } else {
         MessageDigest var7 = MessageDigest.getInstance(var4);
         return doTLS12PRF(var0, var1, var2, var3, var7, var5, var6);
      }
   }

   static byte[] doTLS12PRF(byte[] var0, byte[] var1, byte[] var2, int var3, MessageDigest var4, int var5, int var6) throws DigestException {
      if (var0 == null) {
         var0 = B0;
      }

      if (var0.length > var6) {
         var0 = var4.digest(var0);
      }

      byte[] var7 = new byte[var3];
      byte[] var8;
      byte[] var9;
      switch(var6) {
      case 64:
         var8 = (byte[])HMAC_ipad64.clone();
         var9 = (byte[])HMAC_opad64.clone();
         break;
      case 128:
         var8 = (byte[])HMAC_ipad128.clone();
         var9 = (byte[])HMAC_opad128.clone();
         break;
      default:
         throw new DigestException("Unexpected block size.");
      }

      expand(var4, var5, var0, 0, var0.length, var1, var2, var7, var8, var9);
      return var7;
   }

   static byte[] doTLS10PRF(byte[] var0, byte[] var1, byte[] var2, int var3) throws NoSuchAlgorithmException, DigestException {
      MessageDigest var4 = MessageDigest.getInstance("MD5");
      MessageDigest var5 = MessageDigest.getInstance("SHA1");
      return doTLS10PRF(var0, var1, var2, var3, var4, var5);
   }

   static byte[] doTLS10PRF(byte[] var0, byte[] var1, byte[] var2, int var3, MessageDigest var4, MessageDigest var5) throws DigestException {
      if (var0 == null) {
         var0 = B0;
      }

      int var6 = var0.length >> 1;
      int var7 = var6 + (var0.length & 1);
      byte[] var8 = new byte[var3];
      expand(var4, 16, var0, 0, var7, var1, var2, var8, (byte[])HMAC_ipad64.clone(), (byte[])HMAC_opad64.clone());
      expand(var5, 20, var0, var6, var7, var1, var2, var8, (byte[])HMAC_ipad64.clone(), (byte[])HMAC_opad64.clone());
      return var8;
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

   public static class V10 extends TlsPrfGenerator {
      protected SecretKey engineGenerateKey() {
         return this.engineGenerateKey0(false);
      }
   }

   public static class V12 extends TlsPrfGenerator {
      protected SecretKey engineGenerateKey() {
         return this.engineGenerateKey0(true);
      }
   }
}
