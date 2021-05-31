package org.bc.pqc.jcajce.spec;

import java.security.spec.KeySpec;
import org.bc.pqc.math.linearalgebra.GF2Matrix;

public class McEliecePublicKeySpec implements KeySpec {
   private String oid;
   private int n;
   private int t;
   private GF2Matrix g;

   public McEliecePublicKeySpec(String var1, int var2, int var3, GF2Matrix var4) {
      this.oid = var1;
      this.n = var2;
      this.t = var3;
      this.g = new GF2Matrix(var4);
   }

   public McEliecePublicKeySpec(String var1, int var2, int var3, byte[] var4) {
      this.oid = var1;
      this.n = var3;
      this.t = var2;
      this.g = new GF2Matrix(var4);
   }

   public int getN() {
      return this.n;
   }

   public int getT() {
      return this.t;
   }

   public GF2Matrix getG() {
      return this.g;
   }

   public String getOIDString() {
      return this.oid;
   }
}
