package cn.gmssl.com.sun.crypto.provider;

import cn.gmssl.sun.security.internal.interfaces.TlsMasterSecret;
import cn.gmssl.sun.security.internal.spec.TlsMasterSecretParameterSpec;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

public final class TlsMasterSecretGenerator extends KeyGeneratorSpi {
   private static final String MSG = "TlsMasterSecretGenerator must be initialized using a TlsMasterSecretParameterSpec";
   private TlsMasterSecretParameterSpec spec;
   private int protocolVersion;

   protected void engineInit(SecureRandom var1) {
      throw new InvalidParameterException("TlsMasterSecretGenerator must be initialized using a TlsMasterSecretParameterSpec");
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      if (!(var1 instanceof TlsMasterSecretParameterSpec)) {
         throw new InvalidAlgorithmParameterException("TlsMasterSecretGenerator must be initialized using a TlsMasterSecretParameterSpec");
      } else {
         this.spec = (TlsMasterSecretParameterSpec)var1;
         if (!"RAW".equals(this.spec.getPremasterSecret().getFormat())) {
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
      throw new InvalidParameterException("TlsMasterSecretGenerator must be initialized using a TlsMasterSecretParameterSpec");
   }

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
            byte[] var5;
            if (this.protocolVersion >= 769) {
               byte[] var8 = TlsPrfGenerator.concat(var6, var7);
               var5 = this.protocolVersion >= 771 ? TlsPrfGenerator.doTLS12PRF(var2, TlsPrfGenerator.LABEL_MASTER_SECRET, var8, 48, (String)this.spec.getPRFHashAlg(), this.spec.getPRFHashLength(), this.spec.getPRFBlockSize()) : TlsPrfGenerator.doTLS10PRF(var2, TlsPrfGenerator.LABEL_MASTER_SECRET, var8, 48);
            } else {
               var5 = new byte[48];
               MessageDigest var14 = MessageDigest.getInstance("MD5");
               MessageDigest var9 = MessageDigest.getInstance("SHA");
               byte[] var10 = new byte[20];

               for(int var11 = 0; var11 < 3; ++var11) {
                  var9.update(TlsPrfGenerator.SSL3_CONST[var11]);
                  var9.update(var2);
                  var9.update(var6);
                  var9.update(var7);
                  var9.digest(var10, 0, 20);
                  var14.update(var2);
                  var14.update(var10);
                  var14.digest(var5, var11 << 4, 16);
               }
            }

            return new TlsMasterSecretGenerator.TlsMasterSecretKey(var5, var3, var4);
         } catch (NoSuchAlgorithmException var12) {
            throw new ProviderException(var12);
         } catch (DigestException var13) {
            throw new ProviderException(var13);
         }
      }
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
