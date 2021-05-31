package org.bc.crypto.params;

import org.bc.util.Arrays;

public class DSAValidationParameters {
   private byte[] seed;
   private int counter;

   public DSAValidationParameters(byte[] var1, int var2) {
      this.seed = var1;
      this.counter = var2;
   }

   public int getCounter() {
      return this.counter;
   }

   public byte[] getSeed() {
      return this.seed;
   }

   public int hashCode() {
      return this.counter ^ Arrays.hashCode(this.seed);
   }

   public boolean equals(Object var1) {
      if (!(var1 instanceof DSAValidationParameters)) {
         return false;
      } else {
         DSAValidationParameters var2 = (DSAValidationParameters)var1;
         return var2.counter != this.counter ? false : Arrays.areEqual(this.seed, var2.seed);
      }
   }
}
