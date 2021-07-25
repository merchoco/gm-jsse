package org.bc.jcajce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import org.bc.crypto.BlockCipher;
import org.bc.crypto.BufferedBlockCipher;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.engines.RC6Engine;
import org.bc.crypto.modes.CBCBlockCipher;
import org.bc.crypto.modes.CFBBlockCipher;
import org.bc.crypto.modes.OFBBlockCipher;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bc.jcajce.provider.util.AlgorithmProvider;
import org.bc.jce.provider.BouncyCastleProvider;

public final class RC6 {
   public static class AlgParamGen extends BaseAlgorithmParameterGenerator {
      protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
         throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for RC6 parameter generation.");
      }

      protected AlgorithmParameters engineGenerateParameters() {
         byte[] var1 = new byte[16];
         if (this.random == null) {
            this.random = new SecureRandom();
         }

         this.random.nextBytes(var1);

         try {
            AlgorithmParameters var2 = AlgorithmParameters.getInstance("RC6", BouncyCastleProvider.PROVIDER_NAME);
            var2.init(new IvParameterSpec(var1));
            return var2;
         } catch (Exception var4) {
            throw new RuntimeException(var4.getMessage());
         }
      }
   }

   public static class AlgParams extends IvAlgorithmParameters {
      protected String engineToString() {
         return "RC6 IV";
      }
   }

   public static class CBC extends BaseBlockCipher {
      public CBC() {
         super((BlockCipher)(new CBCBlockCipher(new RC6Engine())), 128);
      }
   }

   public static class CFB extends BaseBlockCipher {
      public CFB() {
         super((BufferedBlockCipher)(new BufferedBlockCipher(new CFBBlockCipher(new RC6Engine(), 128))), 128);
      }
   }

   public static class ECB extends BaseBlockCipher {
      public ECB() {
         super(new RC6Engine());
      }
   }

   public static class KeyGen extends BaseKeyGenerator {
      public KeyGen() {
         super("RC6", 256, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = RC6.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("Cipher.RC6", PREFIX + "$ECB");
         var1.addAlgorithm("KeyGenerator.RC6", PREFIX + "$KeyGen");
         var1.addAlgorithm("AlgorithmParameters.RC6", PREFIX + "$AlgParams");
      }
   }

   public static class OFB extends BaseBlockCipher {
      public OFB() {
         super((BufferedBlockCipher)(new BufferedBlockCipher(new OFBBlockCipher(new RC6Engine(), 128))), 128);
      }
   }
}