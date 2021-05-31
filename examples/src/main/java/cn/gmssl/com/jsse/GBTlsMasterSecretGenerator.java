package cn.gmssl.com.jsse;

import cn.gmssl.sun.security.internal.interfaces.TlsMasterSecret;
import cn.gmssl.sun.security.internal.spec.TlsMasterSecretParameterSpec;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

public class GBTlsMasterSecretGenerator extends KeyGeneratorSpi {
   private static final String MSG = "GBTlsMasterSecretGenerator must be initialized using a TlsMasterSecretParameterSpec";
   private TlsMasterSecretParameterSpec spec;

   protected SecretKey engineGenerateKey() {
      if (this.spec == null) {
         throw new IllegalStateException("TlsMasterSecretGenerator must be initialized");
      } else {
         SecretKey var1 = this.spec.getPremasterSecret();
         byte[] var2 = var1.getEncoded();
         int var3;
         int var4;
         if (var1.getAlgorithm().equals("TlsRsaPremasterSecret")) {
            var3 = var2[0] & 255;
            var4 = var2[1] & 255;
         } else {
            var3 = -1;
            var4 = -1;
         }

         try {
            byte[] var6 = this.spec.getClientRandom();
            byte[] var7 = this.spec.getServerRandom();
            byte[] var8 = TlsUtil.concat(var6, var7);
            int var9 = this.spec.getMajorVersion();
            int var10 = this.spec.getMinorVersion();
            if (var9 != 1) {
               throw new RuntimeException("only gb protocol version supported");
            } else {
               byte[] var5;
               if (var10 == 0) {
                  var5 = TlsUtil.doGBTLS10PRF(var2, TlsUtil.LABEL_MASTER_SECRET, var8, 48);
               } else {
                  if (var10 != 1) {
                     throw new RuntimeException("only gb protocol version supported");
                  }

                  var5 = TlsUtil.doGBTLS11PRF(var2, TlsUtil.LABEL_MASTER_SECRET, var8, 48);
               }

               return new GBTlsMasterSecretGenerator.TlsMasterSecretKey(var5, var3, var4);
            }
         } catch (NoSuchAlgorithmException var11) {
            throw new ProviderException(var11);
         } catch (DigestException var12) {
            throw new ProviderException(var12);
         }
      }
   }

   protected void engineInit(SecureRandom var1) {
      throw new InvalidParameterException("GBTlsMasterSecretGenerator must be initialized using a TlsMasterSecretParameterSpec");
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      if (!(var1 instanceof TlsMasterSecretParameterSpec)) {
         throw new InvalidAlgorithmParameterException("GBTlsMasterSecretGenerator must be initialized using a TlsMasterSecretParameterSpec");
      } else {
         this.spec = (TlsMasterSecretParameterSpec)var1;
         if (!"RAW".equals(this.spec.getPremasterSecret().getFormat())) {
            throw new InvalidAlgorithmParameterException("Key format must be RAW");
         }
      }
   }

   protected void engineInit(int var1, SecureRandom var2) {
      throw new InvalidParameterException("GBTlsMasterSecretGenerator must be initialized using a TlsMasterSecretParameterSpec");
   }

   private static final class TlsMasterSecretKey implements TlsMasterSecret {
      private byte[] key;
      private final int majorVersion;
      private final int minorVersion;

      TlsMasterSecretKey(byte[] var1, int var2, int var3) {
         this.key = var1;
         this.majorVersion = var2;
         this.minorVersion = var3;
      }

      public int getMajorVersion() {
         return this.majorVersion;
      }

      public int getMinorVersion() {
         return this.minorVersion;
      }

      public String getAlgorithm() {
         return "TlsMasterSecret";
      }

      public String getFormat() {
         return "RAW";
      }

      public byte[] getEncoded() {
         return (byte[])this.key.clone();
      }
   }
}
