package org.bc.jcajce.provider.asymmetric.dh;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;
import javax.crypto.spec.DHParameterSpec;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.generators.DHBasicKeyPairGenerator;
import org.bc.crypto.generators.DHParametersGenerator;
import org.bc.crypto.params.DHKeyGenerationParameters;
import org.bc.crypto.params.DHParameters;
import org.bc.crypto.params.DHPrivateKeyParameters;
import org.bc.crypto.params.DHPublicKeyParameters;
import org.bc.jce.provider.BouncyCastleProvider;
import org.bc.util.Integers;

public class KeyPairGeneratorSpi extends KeyPairGenerator {
   private static Hashtable params = new Hashtable();
   private static Object lock = new Object();
   DHKeyGenerationParameters param;
   DHBasicKeyPairGenerator engine = new DHBasicKeyPairGenerator();
   int strength = 1024;
   int certainty = 20;
   SecureRandom random = new SecureRandom();
   boolean initialised = false;

   public KeyPairGeneratorSpi() {
      super("DH");
   }

   public void initialize(int var1, SecureRandom var2) {
      this.strength = var1;
      this.random = var2;
   }

   public void initialize(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      if (!(var1 instanceof DHParameterSpec)) {
         throw new InvalidAlgorithmParameterException("parameter object not a DHParameterSpec");
      } else {
         DHParameterSpec var3 = (DHParameterSpec)var1;
         this.param = new DHKeyGenerationParameters(var2, new DHParameters(var3.getP(), var3.getG(), (BigInteger)null, var3.getL()));
         this.engine.init(this.param);
         this.initialised = true;
      }
   }

   public KeyPair generateKeyPair() {
      if (!this.initialised) {
         Integer var1 = Integers.valueOf(this.strength);
         if (params.containsKey(var1)) {
            this.param = (DHKeyGenerationParameters)params.get(var1);
         } else {
            DHParameterSpec var2 = BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(this.strength);
            if (var2 != null) {
               this.param = new DHKeyGenerationParameters(this.random, new DHParameters(var2.getP(), var2.getG(), (BigInteger)null, var2.getL()));
            } else {
               Object var3 = lock;
               synchronized(lock) {
                  if (params.containsKey(var1)) {
                     this.param = (DHKeyGenerationParameters)params.get(var1);
                  } else {
                     DHParametersGenerator var4 = new DHParametersGenerator();
                     var4.init(this.strength, this.certainty, this.random);
                     this.param = new DHKeyGenerationParameters(this.random, var4.generateParameters());
                     params.put(var1, this.param);
                  }
               }
            }
         }

         this.engine.init(this.param);
         this.initialised = true;
      }

      AsymmetricCipherKeyPair var6 = this.engine.generateKeyPair();
      DHPublicKeyParameters var7 = (DHPublicKeyParameters)var6.getPublic();
      DHPrivateKeyParameters var8 = (DHPrivateKeyParameters)var6.getPrivate();
      return new KeyPair(new BCDHPublicKey(var7), new BCDHPrivateKey(var8));
   }
}
