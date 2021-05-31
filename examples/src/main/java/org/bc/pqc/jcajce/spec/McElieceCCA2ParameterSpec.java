package org.bc.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class McElieceCCA2ParameterSpec implements AlgorithmParameterSpec {
   public static final String DEFAULT_MD = "SHA256";
   private String mdName;

   public McElieceCCA2ParameterSpec() {
      this("SHA256");
   }

   public McElieceCCA2ParameterSpec(String var1) {
      this.mdName = var1;
   }

   public String getMDName() {
      return this.mdName;
   }
}
