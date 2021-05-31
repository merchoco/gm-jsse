package org.bc.pqc.jcajce.provider.mceliece;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.pqc.crypto.mceliece.McElieceCCA2KeyGenerationParameters;
import org.bc.pqc.crypto.mceliece.McElieceCCA2KeyPairGenerator;
import org.bc.pqc.crypto.mceliece.McElieceCCA2Parameters;
import org.bc.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import org.bc.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import org.bc.pqc.crypto.mceliece.McElieceKeyGenerationParameters;
import org.bc.pqc.crypto.mceliece.McElieceKeyPairGenerator;
import org.bc.pqc.crypto.mceliece.McElieceParameters;
import org.bc.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import org.bc.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import org.bc.pqc.jcajce.spec.ECCKeyGenParameterSpec;
import org.bc.pqc.jcajce.spec.McElieceCCA2ParameterSpec;

public abstract class McElieceKeyPairGeneratorSpi extends KeyPairGenerator {
   public McElieceKeyPairGeneratorSpi(String var1) {
      super(var1);
   }

   public static class McEliece extends McElieceKeyPairGeneratorSpi {
      McElieceKeyPairGenerator kpg;

      public McEliece() {
         super("McEliece");
      }

      public void initialize(AlgorithmParameterSpec var1) throws InvalidAlgorithmParameterException {
         this.kpg = new McElieceKeyPairGenerator();
         super.initialize(var1);
         ECCKeyGenParameterSpec var2 = (ECCKeyGenParameterSpec)var1;
         McElieceKeyGenerationParameters var3 = new McElieceKeyGenerationParameters(new SecureRandom(), new McElieceParameters(var2.getM(), var2.getT()));
         this.kpg.init(var3);
      }

      public void initialize(int var1, SecureRandom var2) {
         ECCKeyGenParameterSpec var3 = new ECCKeyGenParameterSpec();

         try {
            this.initialize(var3);
         } catch (InvalidAlgorithmParameterException var5) {
            ;
         }

      }

      public KeyPair generateKeyPair() {
         AsymmetricCipherKeyPair var1 = this.kpg.generateKeyPair();
         McEliecePrivateKeyParameters var2 = (McEliecePrivateKeyParameters)var1.getPrivate();
         McEliecePublicKeyParameters var3 = (McEliecePublicKeyParameters)var1.getPublic();
         return new KeyPair(new BCMcEliecePublicKey(var3), new BCMcEliecePrivateKey(var2));
      }
   }

   public static class McElieceCCA2 extends McElieceKeyPairGeneratorSpi {
      McElieceCCA2KeyPairGenerator kpg;

      public McElieceCCA2() {
         super("McElieceCCA-2");
      }

      public McElieceCCA2(String var1) {
         super(var1);
      }

      public void initialize(AlgorithmParameterSpec var1) throws InvalidAlgorithmParameterException {
         this.kpg = new McElieceCCA2KeyPairGenerator();
         super.initialize(var1);
         ECCKeyGenParameterSpec var2 = (ECCKeyGenParameterSpec)var1;
         McElieceCCA2KeyGenerationParameters var3 = new McElieceCCA2KeyGenerationParameters(new SecureRandom(), new McElieceCCA2Parameters(var2.getM(), var2.getT()));
         this.kpg.init(var3);
      }

      public void initialize(int var1, SecureRandom var2) {
         McElieceCCA2ParameterSpec var3 = new McElieceCCA2ParameterSpec();

         try {
            this.initialize(var3);
         } catch (InvalidAlgorithmParameterException var5) {
            ;
         }

      }

      public KeyPair generateKeyPair() {
         AsymmetricCipherKeyPair var1 = this.kpg.generateKeyPair();
         McElieceCCA2PrivateKeyParameters var2 = (McElieceCCA2PrivateKeyParameters)var1.getPrivate();
         McElieceCCA2PublicKeyParameters var3 = (McElieceCCA2PublicKeyParameters)var1.getPublic();
         return new KeyPair(new BCMcElieceCCA2PublicKey(var3), new BCMcElieceCCA2PrivateKey(var2));
      }
   }
}
