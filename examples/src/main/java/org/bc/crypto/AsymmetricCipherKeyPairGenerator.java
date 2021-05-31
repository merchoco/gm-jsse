package org.bc.crypto;

public interface AsymmetricCipherKeyPairGenerator {
   void init(KeyGenerationParameters var1);

   AsymmetricCipherKeyPair generateKeyPair();
}
