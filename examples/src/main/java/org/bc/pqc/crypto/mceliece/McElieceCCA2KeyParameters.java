package org.bc.pqc.crypto.mceliece;

import org.bc.crypto.params.AsymmetricKeyParameter;

public class McElieceCCA2KeyParameters extends AsymmetricKeyParameter {
   private McElieceCCA2Parameters params;

   public McElieceCCA2KeyParameters(boolean var1, McElieceCCA2Parameters var2) {
      super(var1);
      this.params = var2;
   }

   public McElieceCCA2Parameters getParameters() {
      return this.params;
   }
}
