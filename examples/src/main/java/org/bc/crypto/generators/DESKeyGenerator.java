package org.bc.crypto.generators;

import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.KeyGenerationParameters;
import org.bc.crypto.params.DESParameters;

public class DESKeyGenerator extends CipherKeyGenerator {
   public void init(KeyGenerationParameters var1) {
      super.init(var1);
      if (this.strength != 0 && this.strength != 7) {
         if (this.strength != 8) {
            throw new IllegalArgumentException("DES key must be 64 bits long.");
         }
      } else {
         this.strength = 8;
      }

   }

   public byte[] generateKey() {
      byte[] var1 = new byte[8];

      do {
         this.random.nextBytes(var1);
         DESParameters.setOddParity(var1);
      } while(DESParameters.isWeakKey(var1, 0));

      return var1;
   }
}
