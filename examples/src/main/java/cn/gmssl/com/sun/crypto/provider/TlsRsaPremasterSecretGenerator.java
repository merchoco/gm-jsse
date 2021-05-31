package cn.gmssl.com.sun.crypto.provider;

import cn.gmssl.sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public final class TlsRsaPremasterSecretGenerator extends KeyGeneratorSpi {
   private static final String MSG = "TlsRsaPremasterSecretGenerator must be initialized using a TlsRsaPremasterSecretParameterSpec";
   private TlsRsaPremasterSecretParameterSpec spec;
   private SecureRandom random;

   protected void engineInit(SecureRandom var1) {
      throw new InvalidParameterException("TlsRsaPremasterSecretGenerator must be initialized using a TlsRsaPremasterSecretParameterSpec");
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      if (!(var1 instanceof TlsRsaPremasterSecretParameterSpec)) {
         throw new InvalidAlgorithmParameterException("TlsRsaPremasterSecretGenerator must be initialized using a TlsRsaPremasterSecretParameterSpec");
      } else {
         this.spec = (TlsRsaPremasterSecretParameterSpec)var1;
         this.random = var2;
      }
   }

   protected void engineInit(int var1, SecureRandom var2) {
      throw new InvalidParameterException("TlsRsaPremasterSecretGenerator must be initialized using a TlsRsaPremasterSecretParameterSpec");
   }

   protected SecretKey engineGenerateKey() {
      if (this.spec == null) {
         throw new IllegalStateException("TlsRsaPremasterSecretGenerator must be initialized");
      } else {
         if (this.random == null) {
            this.random = new SecureRandom();
         }

         byte[] var1 = new byte[48];
         this.random.nextBytes(var1);
         var1[0] = (byte)this.spec.getMajorVersion();
         var1[1] = (byte)this.spec.getMinorVersion();
         return new SecretKeySpec(var1, "TlsRsaPremasterSecret");
      }
   }
}
