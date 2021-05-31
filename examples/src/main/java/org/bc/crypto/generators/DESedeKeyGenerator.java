package org.bc.crypto.generators;

import org.bc.crypto.KeyGenerationParameters;
import org.bc.crypto.params.DESedeParameters;

public class DESedeKeyGenerator extends DESKeyGenerator {
   public void init(KeyGenerationParameters var1) {
      this.random = var1.getRandom();
      this.strength = (var1.getStrength() + 7) / 8;
      if (this.strength != 0 && this.strength != 21) {
         if (this.strength == 14) {
            this.strength = 16;
         } else if (this.strength != 24 && this.strength != 16) {
            throw new IllegalArgumentException("DESede key must be 192 or 128 bits long.");
         }
      } else {
         this.strength = 24;
      }

   }

   public byte[] generateKey() {
      byte[] var1 = new byte[this.strength];

      do {
         this.random.nextBytes(var1);
         DESedeParameters.setOddParity(var1);
      } while(DESedeParameters.isWeakKey(var1, 0, var1.length));

      return var1;
   }
}
