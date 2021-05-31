package org.bc.pqc.jcajce.spec;

import java.security.spec.KeySpec;
import org.bc.pqc.math.linearalgebra.GF2Matrix;

public class McElieceCCA2PublicKeySpec implements KeySpec {
   private String oid;
   private int n;
   private int t;
   private GF2Matrix matrixG;

   public McElieceCCA2PublicKeySpec(String var1, int var2, int var3, GF2Matrix var4) {
      this.oid = var1;
      this.n = var2;
      this.t = var3;
      this.matrixG = new GF2Matrix(var4);
   }

   public McElieceCCA2PublicKeySpec(String var1, int var2, int var3, byte[] var4) {
      this.oid = var1;
      this.n = var2;
      this.t = var3;
      this.matrixG = new GF2Matrix(var4);
   }

   public int getN() {
      return this.n;
   }

   public int getT() {
      return this.t;
   }

   public GF2Matrix getMatrixG() {
      return this.matrixG;
   }

   public String getOIDString() {
      return this.oid;
   }
}
