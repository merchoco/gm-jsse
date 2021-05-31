package org.bc.pqc.crypto.mceliece;

import org.bc.pqc.math.linearalgebra.GF2Matrix;
import org.bc.pqc.math.linearalgebra.GF2mField;
import org.bc.pqc.math.linearalgebra.Permutation;
import org.bc.pqc.math.linearalgebra.PolynomialGF2mSmallM;

public class McElieceCCA2PrivateKeyParameters extends McElieceCCA2KeyParameters {
   private String oid;
   private int n;
   private int k;
   private GF2mField field;
   private PolynomialGF2mSmallM goppaPoly;
   private Permutation p;
   private GF2Matrix h;
   private PolynomialGF2mSmallM[] qInv;

   public McElieceCCA2PrivateKeyParameters(String var1, int var2, int var3, GF2mField var4, PolynomialGF2mSmallM var5, Permutation var6, GF2Matrix var7, PolynomialGF2mSmallM[] var8, McElieceCCA2Parameters var9) {
      super(true, var9);
      this.oid = var1;
      this.n = var2;
      this.k = var3;
      this.field = var4;
      this.goppaPoly = var5;
      this.p = var6;
      this.h = var7;
      this.qInv = var8;
   }

   public McElieceCCA2PrivateKeyParameters(String var1, int var2, int var3, byte[] var4, byte[] var5, byte[] var6, byte[] var7, byte[][] var8, McElieceCCA2Parameters var9) {
      super(true, var9);
      this.oid = var1;
      this.n = var2;
      this.k = var3;
      this.field = new GF2mField(var4);
      this.goppaPoly = new PolynomialGF2mSmallM(this.field, var5);
      this.p = new Permutation(var6);
      this.h = new GF2Matrix(var7);
      this.qInv = new PolynomialGF2mSmallM[var8.length];

      for(int var10 = 0; var10 < var8.length; ++var10) {
         this.qInv[var10] = new PolynomialGF2mSmallM(this.field, var8[var10]);
      }

   }

   public int getN() {
      return this.n;
   }

   public int getK() {
      return this.k;
   }

   public int getT() {
      return this.goppaPoly.getDegree();
   }

   public GF2mField getField() {
      return this.field;
   }

   public PolynomialGF2mSmallM getGoppaPoly() {
      return this.goppaPoly;
   }

   public Permutation getP() {
      return this.p;
   }

   public GF2Matrix getH() {
      return this.h;
   }

   public PolynomialGF2mSmallM[] getQInv() {
      return this.qInv;
   }

   public String getOIDString() {
      return this.oid;
   }
}
