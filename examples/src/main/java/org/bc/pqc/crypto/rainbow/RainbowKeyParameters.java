package org.bc.pqc.crypto.rainbow;

import org.bc.crypto.params.AsymmetricKeyParameter;

public class RainbowKeyParameters extends AsymmetricKeyParameter {
   private int docLength;

   public RainbowKeyParameters(boolean var1, int var2) {
      super(var1);
      this.docLength = var2;
   }

   public int getDocLength() {
      return this.docLength;
   }
}
