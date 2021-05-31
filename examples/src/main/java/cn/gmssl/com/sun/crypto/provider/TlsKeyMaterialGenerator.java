package cn.gmssl.com.sun.crypto.provider;

import cn.gmssl.sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import cn.gmssl.sun.security.internal.spec.TlsKeyMaterialSpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class TlsKeyMaterialGenerator extends KeyGeneratorSpi {
   private static final String MSG = "TlsKeyMaterialGenerator must be initialized using a TlsKeyMaterialParameterSpec";
   private TlsKeyMaterialParameterSpec spec;
   private int protocolVersion;

   protected void engineInit(SecureRandom var1) {
      throw new InvalidParameterException("TlsKeyMaterialGenerator must be initialized using a TlsKeyMaterialParameterSpec");
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      if (!(var1 instanceof TlsKeyMaterialParameterSpec)) {
         throw new InvalidAlgorithmParameterException("TlsKeyMaterialGenerator must be initialized using a TlsKeyMaterialParameterSpec");
      } else {
         this.spec = (TlsKeyMaterialParameterSpec)var1;
         if (!"RAW".equals(this.spec.getMasterSecret().getFormat())) {
            throw new InvalidAlgorithmParameterException("Key format must be RAW");
         } else {
            this.protocolVersion = this.spec.getMajorVersion() << 8 | this.spec.getMinorVersion();
            if (this.protocolVersion < 768 || this.protocolVersion > 771) {
               throw new InvalidAlgorithmParameterException("Only SSL 3.0, TLS 1.0/1.1/1.2 supported");
            }
         }
      }
   }

   protected void engineInit(int var1, SecureRandom var2) {
      throw new InvalidParameterException("TlsKeyMaterialGenerator must be initialized using a TlsKeyMaterialParameterSpec");
   }

   protected SecretKey engineGenerateKey() {
      if (this.spec == null) {
         throw new IllegalStateException("TlsKeyMaterialGenerator must be initialized");
      } else {
         try {
            return this.engineGenerateKey0();
         } catch (GeneralSecurityException var2) {
            throw new ProviderException(var2);
         }
      }
   }

   private SecretKey engineGenerateKey0() throws GeneralSecurityException {
      byte[] var1 = this.spec.getMasterSecret().getEncoded();
      byte[] var2 = this.spec.getClientRandom();
      byte[] var3 = this.spec.getServerRandom();
      SecretKeySpec var4 = null;
      SecretKeySpec var5 = null;
      SecretKeySpec var6 = null;
      SecretKeySpec var7 = null;
      IvParameterSpec var8 = null;
      IvParameterSpec var9 = null;
      int var10 = this.spec.getMacKeyLength();
      int var11 = this.spec.getExpandedCipherKeyLength();
      boolean var12 = var11 != 0;
      int var13 = this.spec.getCipherKeyLength();
      int var14 = this.spec.getIvLength();
      int var15 = var10 + var13 + (var12 ? 0 : var14);
      var15 <<= 1;
      byte[] var16 = new byte[var15];
      MessageDigest var17 = null;
      MessageDigest var18 = null;
      byte[] var19;
      if (this.protocolVersion >= 771) {
         var19 = TlsPrfGenerator.concat(var3, var2);
         var16 = TlsPrfGenerator.doTLS12PRF(var1, TlsPrfGenerator.LABEL_KEY_EXPANSION, var19, var15, this.spec.getPRFHashAlg(), this.spec.getPRFHashLength(), this.spec.getPRFBlockSize());
      } else if (this.protocolVersion >= 769) {
         var17 = MessageDigest.getInstance("MD5");
         var18 = MessageDigest.getInstance("SHA1");
         var19 = TlsPrfGenerator.concat(var3, var2);
         var16 = TlsPrfGenerator.doTLS10PRF(var1, TlsPrfGenerator.LABEL_KEY_EXPANSION, var19, var15, var17, var18);
      } else {
         var17 = MessageDigest.getInstance("MD5");
         var18 = MessageDigest.getInstance("SHA1");
         var16 = new byte[var15];
         var19 = new byte[20];
         int var20 = 0;

         for(int var21 = var15; var21 > 0; var21 -= 16) {
            var18.update(TlsPrfGenerator.SSL3_CONST[var20]);
            var18.update(var1);
            var18.update(var3);
            var18.update(var2);
            var18.digest(var19, 0, 20);
            var17.update(var1);
            var17.update(var19);
            if (var21 >= 16) {
               var17.digest(var16, var20 << 4, 16);
            } else {
               var17.digest(var19, 0, 16);
               System.arraycopy(var19, 0, var16, var20 << 4, var21);
            }

            ++var20;
         }
      }

      byte var26 = 0;
      byte[] var28 = new byte[var10];
      System.arraycopy(var16, var26, var28, 0, var10);
      int var27 = var26 + var10;
      var4 = new SecretKeySpec(var28, "Mac");
      System.arraycopy(var16, var27, var28, 0, var10);
      var27 += var10;
      var5 = new SecretKeySpec(var28, "Mac");
      if (var13 == 0) {
         return new TlsKeyMaterialSpec(var4, var5);
      } else {
         String var29 = this.spec.getCipherAlgorithm();
         byte[] var22 = new byte[var13];
         System.arraycopy(var16, var27, var22, 0, var13);
         var27 += var13;
         byte[] var23 = new byte[var13];
         System.arraycopy(var16, var27, var23, 0, var13);
         var27 += var13;
         if (!var12) {
            var6 = new SecretKeySpec(var22, var29);
            var7 = new SecretKeySpec(var23, var29);
            if (var14 != 0) {
               var28 = new byte[var14];
               System.arraycopy(var16, var27, var28, 0, var14);
               var27 += var14;
               var8 = new IvParameterSpec(var28);
               System.arraycopy(var16, var27, var28, 0, var14);
               int var10000 = var27 + var14;
               var9 = new IvParameterSpec(var28);
            }
         } else {
            if (this.protocolVersion >= 770) {
               throw new RuntimeException("Internal Error:  TLS 1.1+ should not be negotiatingexportable ciphersuites");
            }

            if (this.protocolVersion == 769) {
               byte[] var24 = TlsPrfGenerator.concat(var2, var3);
               var28 = TlsPrfGenerator.doTLS10PRF(var22, TlsPrfGenerator.LABEL_CLIENT_WRITE_KEY, var24, var11, var17, var18);
               var6 = new SecretKeySpec(var28, var29);
               var28 = TlsPrfGenerator.doTLS10PRF(var23, TlsPrfGenerator.LABEL_SERVER_WRITE_KEY, var24, var11, var17, var18);
               var7 = new SecretKeySpec(var28, var29);
               if (var14 != 0) {
                  var28 = new byte[var14];
                  byte[] var25 = TlsPrfGenerator.doTLS10PRF((byte[])null, TlsPrfGenerator.LABEL_IV_BLOCK, var24, var14 << 1, var17, var18);
                  System.arraycopy(var25, 0, var28, 0, var14);
                  var8 = new IvParameterSpec(var28);
                  System.arraycopy(var25, var14, var28, 0, var14);
                  var9 = new IvParameterSpec(var28);
               }
            } else {
               var28 = new byte[var11];
               var17.update(var22);
               var17.update(var2);
               var17.update(var3);
               System.arraycopy(var17.digest(), 0, var28, 0, var11);
               var6 = new SecretKeySpec(var28, var29);
               var17.update(var23);
               var17.update(var3);
               var17.update(var2);
               System.arraycopy(var17.digest(), 0, var28, 0, var11);
               var7 = new SecretKeySpec(var28, var29);
               if (var14 != 0) {
                  var28 = new byte[var14];
                  var17.update(var2);
                  var17.update(var3);
                  System.arraycopy(var17.digest(), 0, var28, 0, var14);
                  var8 = new IvParameterSpec(var28);
                  var17.update(var3);
                  var17.update(var2);
                  System.arraycopy(var17.digest(), 0, var28, 0, var14);
                  var9 = new IvParameterSpec(var28);
               }
            }
         }

         return new TlsKeyMaterialSpec(var4, var5, var6, var8, var7, var9);
      }
   }
}
