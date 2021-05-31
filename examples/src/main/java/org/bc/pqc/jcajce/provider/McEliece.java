package org.bc.pqc.jcajce.provider;

import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bc.pqc.asn1.PQCObjectIdentifiers;

public class McEliece {
   private static final String PREFIX = "org.bc.pqc.jcajce.provider.mceliece.";

   public static class Mappings extends AsymmetricAlgorithmProvider {
      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("KeyPairGenerator.McElieceKobaraImai", "org.bc.pqc.jcajce.provider.mceliece.McElieceKeyPairGeneratorSpi$McElieceCCA2");
         var1.addAlgorithm("KeyPairGenerator.McEliecePointcheval", "org.bc.pqc.jcajce.provider.mceliece.McElieceKeyPairGeneratorSpi$McElieceCCA2");
         var1.addAlgorithm("KeyPairGenerator.McElieceFujisaki", "org.bc.pqc.jcajce.provider.mceliece.McElieceKeyPairGeneratorSpi$McElieceCCA2");
         var1.addAlgorithm("KeyPairGenerator.McEliecePKCS", "org.bc.pqc.jcajce.provider.mceliece.McElieceKeyPairGeneratorSpi$McEliece");
         var1.addAlgorithm("KeyPairGenerator." + PQCObjectIdentifiers.mcEliece, "org.bc.pqc.jcajce.provider.mceliece.McElieceKeyPairGeneratorSpi$McEliece");
         var1.addAlgorithm("KeyPairGenerator." + PQCObjectIdentifiers.mcElieceCca2, "org.bc.pqc.jcajce.provider.mceliece.McElieceKeyPairGeneratorSpi$McElieceCCA2");
         var1.addAlgorithm("Cipher.McEliecePointcheval", "org.bc.pqc.jcajce.provider.mceliece.McEliecePointchevalCipherSpi$McEliecePointcheval");
         var1.addAlgorithm("Cipher.McEliecePointchevalWithSHA1", "org.bc.pqc.jcajce.provider.mceliece.McEliecePointchevalCipherSpi$McEliecePointcheval");
         var1.addAlgorithm("Cipher.McEliecePointchevalWithSHA224", "org.bc.pqc.jcajce.provider.mceliece.McEliecePointchevalCipherSpi$McEliecePointcheval224");
         var1.addAlgorithm("Cipher.McEliecePointchevalWithSHA256", "org.bc.pqc.jcajce.provider.mceliece.McEliecePointchevalCipherSpi$McEliecePointcheval256");
         var1.addAlgorithm("Cipher.McEliecePointchevalWithSHA384", "org.bc.pqc.jcajce.provider.mceliece.McEliecePointchevalCipherSpi$McEliecePointcheval384");
         var1.addAlgorithm("Cipher.McEliecePointchevalWithSHA512", "org.bc.pqc.jcajce.provider.mceliece.McEliecePointchevalCipherSpi$McEliecePointcheval512");
         var1.addAlgorithm("Cipher.McEliecePKCS", "org.bc.pqc.jcajce.provider.mceliece.McEliecePKCSCipherSpi$McEliecePKCS");
         var1.addAlgorithm("Cipher.McEliecePKCSWithSHA1", "org.bc.pqc.jcajce.provider.mceliece.McEliecePKCSCipherSpi$McEliecePKCS");
         var1.addAlgorithm("Cipher.McEliecePKCSWithSHA224", "org.bc.pqc.jcajce.provider.mceliece.McEliecePKCSCipherSpi$McEliecePKCS224");
         var1.addAlgorithm("Cipher.McEliecePKCSWithSHA256", "org.bc.pqc.jcajce.provider.mceliece.McEliecePKCSCipherSpi$McEliecePKCS256");
         var1.addAlgorithm("Cipher.McEliecePKCSWithSHA384", "org.bc.pqc.jcajce.provider.mceliece.McEliecePKCSCipherSpi$McEliecePKCS384");
         var1.addAlgorithm("Cipher.McEliecePKCSWithSHA512", "org.bc.pqc.jcajce.provider.mceliece.McEliecePKCSCipherSpi$McEliecePKCS512");
         var1.addAlgorithm("Cipher.McElieceKobaraImai", "org.bc.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi$McElieceKobaraImai");
         var1.addAlgorithm("Cipher.McElieceKobaraImaiWithSHA1", "org.bc.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi$McElieceKobaraImai");
         var1.addAlgorithm("Cipher.McElieceKobaraImaiWithSHA224", "org.bc.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi$McElieceKobaraImai224");
         var1.addAlgorithm("Cipher.McElieceKobaraImaiWithSHA256", "org.bc.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi$McElieceKobaraImai256");
         var1.addAlgorithm("Cipher.McElieceKobaraImaiWithSHA384", "org.bc.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi$McElieceKobaraImai384");
         var1.addAlgorithm("Cipher.McElieceKobaraImaiWithSHA512", "org.bc.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi$McElieceKobaraImai512");
         var1.addAlgorithm("Cipher.McElieceFujisaki", "org.bc.pqc.jcajce.provider.mceliece.McElieceFujisakiCipherSpi$McElieceFujisaki");
         var1.addAlgorithm("Cipher.McElieceFujisakiWithSHA1", "org.bc.pqc.jcajce.provider.mceliece.McElieceFujisakiCipherSpi$McElieceFujisaki");
         var1.addAlgorithm("Cipher.McElieceFujisakiWithSHA224", "org.bc.pqc.jcajce.provider.mceliece.McElieceFujisakiCipherSpi$McElieceFujisaki224");
         var1.addAlgorithm("Cipher.McElieceFujisakiWithSHA256", "org.bc.pqc.jcajce.provider.mceliece.McElieceFujisakiCipherSpi$McElieceFujisaki256");
         var1.addAlgorithm("Cipher.McElieceFujisakiWithSHA384", "org.bc.pqc.jcajce.provider.mceliece.McElieceFujisakiCipherSpi$McElieceFujisaki384");
         var1.addAlgorithm("Cipher.McElieceFujisakiWithSHA512", "org.bc.pqc.jcajce.provider.mceliece.McElieceFujisakiCipherSpi$McElieceFujisaki512");
      }
   }
}
