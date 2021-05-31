package org.bc.pqc.crypto.rainbow;

import java.security.SecureRandom;
import org.bc.crypto.KeyGenerationParameters;

public class RainbowKeyGenerationParameters extends KeyGenerationParameters {
   private RainbowParameters params;

   public RainbowKeyGenerationParameters(SecureRandom var1, RainbowParameters var2) {
      super(var1, var2.getVi()[var2.getVi().length - 1] - var2.getVi()[0]);
      this.params = var2;
   }

   public RainbowParameters getParameters() {
      return this.params;
   }
}
