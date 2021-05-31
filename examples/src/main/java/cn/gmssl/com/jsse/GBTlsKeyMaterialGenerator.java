package cn.gmssl.com.jsse;

import cn.gmssl.sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import cn.gmssl.sun.security.internal.spec.TlsKeyMaterialSpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class GBTlsKeyMaterialGenerator extends KeyGeneratorSpi {
   private static final String MSG = "GBTlsKeyMaterialGenerator must be initialized using a TlsKeyMaterialParameterSpec";
   private TlsKeyMaterialParameterSpec spec;

   protected void engineInit(SecureRandom var1) {
      throw new InvalidParameterException("GBTlsKeyMaterialGenerator must be initialized using a TlsKeyMaterialParameterSpec");
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      if (!(var1 instanceof TlsKeyMaterialParameterSpec)) {
         throw new InvalidAlgorithmParameterException("GBTlsKeyMaterialGenerator must be initialized using a TlsKeyMaterialParameterSpec");
      } else {
         this.spec = (TlsKeyMaterialParameterSpec)var1;
         if (!"RAW".equals(this.spec.getMasterSecret().getFormat())) {
            throw new InvalidAlgorithmParameterException("Key format must be RAW");
         } else if (this.spec.getMajorVersion() != 1) {
            throw new InvalidAlgorithmParameterException("Only GB TLS supported");
         }
      }
   }

   protected void engineInit(int var1, SecureRandom var2) {
      throw new InvalidParameterException("GBTlsKeyMaterialGenerator must be initialized using a TlsKeyMaterialParameterSpec");
   }

   protected SecretKey engineGenerateKey() {
      if (this.spec == null) {
         throw new IllegalStateException("GBTlsKeyMaterialGenerator must be initialized");
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
      byte[] var17 = TlsUtil.concat(var3, var2);
      int var18 = this.spec.getMinorVersion();
      if (var18 == 0) {
         var16 = TlsUtil.doGBTLS10PRF(var1, TlsUtil.LABEL_KEY_EXPANSION, var17, var15);
      } else {
         var16 = TlsUtil.doGBTLS11PRF(var1, TlsUtil.LABEL_KEY_EXPANSION, var17, var15);
      }

      byte var19 = 0;
      byte[] var20 = new byte[var10];
      System.arraycopy(var16, var19, var20, 0, var10);
      int var24 = var19 + var10;
      var4 = new SecretKeySpec(var20, "Mac");
      System.arraycopy(var16, var24, var20, 0, var10);
      var24 += var10;
      var5 = new SecretKeySpec(var20, "Mac");
      if (var13 == 0) {
         return new TlsKeyMaterialSpec(var4, var5);
      } else {
         String var21 = this.spec.getCipherAlgorithm();
         byte[] var22 = new byte[var13];
         System.arraycopy(var16, var24, var22, 0, var13);
         var24 += var13;
         byte[] var23 = new byte[var13];
         System.arraycopy(var16, var24, var23, 0, var13);
         var24 += var13;
         if (!var12) {
            var6 = new SecretKeySpec(var22, var21);
            var7 = new SecretKeySpec(var23, var21);
            if (var14 != 0) {
               var20 = new byte[var14];
               System.arraycopy(var16, var24, var20, 0, var14);
               var24 += var14;
               var8 = new IvParameterSpec(var20);
               System.arraycopy(var16, var24, var20, 0, var14);
               int var10000 = var24 + var14;
               var9 = new IvParameterSpec(var20);
            }
         }

         return new TlsKeyMaterialSpec(var4, var5, var6, var8, var7, var9);
      }
   }
}
