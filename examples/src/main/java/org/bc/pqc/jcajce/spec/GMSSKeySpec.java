package org.bc.pqc.jcajce.spec;

import java.security.spec.KeySpec;
import org.bc.pqc.crypto.gmss.GMSSParameters;

public class GMSSKeySpec implements KeySpec {
   private GMSSParameters gmssParameterSet;

   protected GMSSKeySpec(GMSSParameters var1) {
      this.gmssParameterSet = var1;
   }

   public GMSSParameters getParameters() {
      return this.gmssParameterSet;
   }
}
