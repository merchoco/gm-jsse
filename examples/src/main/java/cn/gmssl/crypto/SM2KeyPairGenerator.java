package cn.gmssl.crypto;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.generators.ECKeyPairGenerator;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECKeyGenerationParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bc.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bc.jcajce.provider.asymmetric.ec.EC5Util;
import org.bc.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bc.jcajce.provider.config.ProviderConfiguration;
import org.bc.jce.provider.BouncyCastleProvider;
import org.bc.jce.spec.ECParameterSpec;
import org.bc.math.ec.ECCurve;
import org.bc.math.ec.ECPoint;

public class SM2KeyPairGenerator extends KeyPairGeneratorSpi {
   private ECKeyPairGenerator engine = new ECKeyPairGenerator();
   private String algorithm = null;
   private boolean initialised = false;
   private int strength = 256;
   private AlgorithmParameterSpec params = null;
   private ProviderConfiguration configuration;

   public SM2KeyPairGenerator() {
      super("SM2");
      this.algorithm = "SM2";
      this.configuration = BouncyCastleProvider.CONFIGURATION;
   }

   public void initialize(int var1, SecureRandom var2) {
      this.strength = var1;
      if (var1 == 256) {
         try {
            ECParameterSpec var3 = SM2Util.getSM2NamedCuve();
            this.initialize(var3, var2);
         } catch (InvalidAlgorithmParameterException var4) {
            throw new InvalidParameterException("key size not configurable.");
         }
      } else {
         throw new InvalidParameterException("unknown key size.");
      }
   }

   public void initialize(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      this.params = var1;
      if (var1 instanceof ECParameterSpec) {
         ECParameterSpec var3 = (ECParameterSpec)var1;
         ECKeyGenerationParameters var4 = new ECKeyGenerationParameters(new ECDomainParameters(var3.getCurve(), var3.getG(), var3.getN()), var2);
         this.engine.init(var4);
         this.initialised = true;
      } else {
         if (!(var1 instanceof java.security.spec.ECParameterSpec)) {
            throw new InvalidAlgorithmParameterException("parameter object not a ECParameterSpec");
         }

         java.security.spec.ECParameterSpec var7 = (java.security.spec.ECParameterSpec)var1;
         ECCurve var8 = EC5Util.convertCurve(var7.getCurve());
         ECPoint var5 = EC5Util.convertPoint(var8, var7.getGenerator(), false);
         ECKeyGenerationParameters var6 = new ECKeyGenerationParameters(new ECDomainParameters(var8, var5, var7.getOrder(), BigInteger.valueOf((long)var7.getCofactor())), var2);
         this.engine.init(var6);
         this.initialised = true;
      }

   }

   public KeyPair generateKeyPair() {
      if (!this.initialised) {
         this.initialize(this.strength, new SecureRandom());
      }

      AsymmetricCipherKeyPair var1 = this.engine.generateKeyPair();
      ECPublicKeyParameters var2 = (ECPublicKeyParameters)var1.getPublic();
      ECPrivateKeyParameters var3 = (ECPrivateKeyParameters)var1.getPrivate();
      BCECPublicKey var5;
      if (this.params instanceof ECParameterSpec) {
         ECParameterSpec var6 = (ECParameterSpec)this.params;
         var5 = new BCECPublicKey(this.algorithm, var2, var6, this.configuration);
         return new KeyPair(var5, new BCECPrivateKey(this.algorithm, var3, var5, var6, this.configuration));
      } else {
         java.security.spec.ECParameterSpec var4 = (java.security.spec.ECParameterSpec)this.params;
         var5 = new BCECPublicKey(this.algorithm, var2, var4, this.configuration);
         return new KeyPair(var5, new BCECPrivateKey(this.algorithm, var3, var5, var4, this.configuration));
      }
   }
}
