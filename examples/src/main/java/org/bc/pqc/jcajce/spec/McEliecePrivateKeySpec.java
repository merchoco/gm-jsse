package org.bc.pqc.jcajce.spec;

import java.security.spec.KeySpec;
import org.bc.pqc.math.linearalgebra.GF2Matrix;
import org.bc.pqc.math.linearalgebra.GF2mField;
import org.bc.pqc.math.linearalgebra.Permutation;
import org.bc.pqc.math.linearalgebra.PolynomialGF2mSmallM;

public class McEliecePrivateKeySpec implements KeySpec {
   private String oid;
   private int n;
   private int k;
   private GF2mField field;
   private PolynomialGF2mSmallM goppaPoly;
   private GF2Matrix sInv;
   private Permutation p1;
   private Permutation p2;
   private GF2Matrix h;
   private PolynomialGF2mSmallM[] qInv;

   public McEliecePrivateKeySpec(String var1, int var2, int var3, GF2mField var4, PolynomialGF2mSmallM var5, GF2Matrix var6, Permutation var7, Permutation var8, GF2Matrix var9, PolynomialGF2mSmallM[] var10) {
      this.oid = var1;
      this.k = var3;
      this.n = var2;
      this.field = var4;
      this.goppaPoly = var5;
      this.sInv = var6;
      this.p1 = var7;
      this.p2 = var8;
      this.h = var9;
      this.qInv = var10;
   }

   public McEliecePrivateKeySpec(String var1, int var2, int var3, byte[] var4, byte[] var5, byte[] var6, byte[] var7, byte[] var8, byte[] var9, byte[][] var10) {
      this.oid = var1;
      this.n = var2;
      this.k = var3;
      this.field = new GF2mField(var4);
      this.goppaPoly = new PolynomialGF2mSmallM(this.field, var5);
      this.sInv = new GF2Matrix(var6);
      this.p1 = new Permutation(var7);
      this.p2 = new Permutation(var8);
      this.h = new GF2Matrix(var9);
      this.qInv = new PolynomialGF2mSmallM[var10.length];

      for(int var11 = 0; var11 < var10.length; ++var11) {
         this.qInv[var11] = new PolynomialGF2mSmallM(this.field, var10[var11]);
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

   public GF2Matrix getSInv() {
      return this.sInv;
   }

   public Permutation getP1() {
      return this.p1;
   }

   public Permutation getP2() {
      return this.p2;
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
