package org.bc.pqc.jcajce.spec;

import java.security.spec.KeySpec;
import org.bc.pqc.math.linearalgebra.GF2Matrix;
import org.bc.pqc.math.linearalgebra.GF2mField;
import org.bc.pqc.math.linearalgebra.Permutation;
import org.bc.pqc.math.linearalgebra.PolynomialGF2mSmallM;

public class McElieceCCA2PrivateKeySpec implements KeySpec {
   private String oid;
   private int n;
   private int k;
   private GF2mField field;
   private PolynomialGF2mSmallM goppaPoly;
   private Permutation p;
   private GF2Matrix h;
   private PolynomialGF2mSmallM[] qInv;

   public McElieceCCA2PrivateKeySpec(String var1, int var2, int var3, GF2mField var4, PolynomialGF2mSmallM var5, Permutation var6, GF2Matrix var7, PolynomialGF2mSmallM[] var8) {
      this.oid = var1;
      this.n = var2;
      this.k = var3;
      this.field = var4;
      this.goppaPoly = var5;
      this.p = var6;
      this.h = var7;
      this.qInv = var8;
   }

   public McElieceCCA2PrivateKeySpec(String var1, int var2, int var3, byte[] var4, byte[] var5, byte[] var6, byte[] var7, byte[][] var8) {
      this.oid = var1;
      this.n = var2;
      this.k = var3;
      this.field = new GF2mField(var4);
      this.goppaPoly = new PolynomialGF2mSmallM(this.field, var5);
      this.p = new Permutation(var6);
      this.h = new GF2Matrix(var7);
      this.qInv = new PolynomialGF2mSmallM[var8.length];

      for(int var9 = 0; var9 < var8.length; ++var9) {
         this.qInv[var9] = new PolynomialGF2mSmallM(this.field, var8[var9]);
      }

   }

   public int getN() {
      return this.n;
   }

   public int getK() {
      return this.k;
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
