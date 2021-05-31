package org.bc.pqc.crypto.mceliece;

import org.bc.pqc.math.linearalgebra.GF2Matrix;

public class McElieceCCA2PublicKeyParameters extends McElieceCCA2KeyParameters {
   private String oid;
   private int n;
   private int t;
   private GF2Matrix matrixG;

   public McElieceCCA2PublicKeyParameters(String var1, int var2, int var3, GF2Matrix var4, McElieceCCA2Parameters var5) {
      super(false, var5);
      this.oid = var1;
      this.n = var2;
      this.t = var3;
      this.matrixG = new GF2Matrix(var4);
   }

   public McElieceCCA2PublicKeyParameters(String var1, int var2, int var3, byte[] var4, McElieceCCA2Parameters var5) {
      super(false, var5);
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

   public int getK() {
      return this.matrixG.getNumRows();
   }

   public String getOIDString() {
      return this.oid;
   }
}
