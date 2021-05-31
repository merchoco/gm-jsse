package org.bc.pqc.jcajce.spec;

import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;
import org.bc.pqc.math.linearalgebra.PolynomialRingGF2;

public class ECCKeyGenParameterSpec implements AlgorithmParameterSpec {
   public static final int DEFAULT_M = 11;
   public static final int DEFAULT_T = 50;
   private int m;
   private int t;
   private int n;
   private int fieldPoly;

   public ECCKeyGenParameterSpec() {
      this(11, 50);
   }

   public ECCKeyGenParameterSpec(int var1) throws InvalidParameterException {
      if (var1 < 1) {
         throw new InvalidParameterException("key size must be positive");
      } else {
         this.m = 0;

         for(this.n = 1; this.n < var1; ++this.m) {
            this.n <<= 1;
         }

         this.t = this.n >>> 1;
         this.t /= this.m;
         this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(this.m);
      }
   }

   public ECCKeyGenParameterSpec(int var1, int var2) throws InvalidParameterException {
      if (var1 < 1) {
         throw new InvalidParameterException("m must be positive");
      } else if (var1 > 32) {
         throw new InvalidParameterException("m is too large");
      } else {
         this.m = var1;
         this.n = 1 << var1;
         if (var2 < 0) {
            throw new InvalidParameterException("t must be positive");
         } else if (var2 > this.n) {
            throw new InvalidParameterException("t must be less than n = 2^m");
         } else {
            this.t = var2;
            this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(var1);
         }
      }
   }

   public ECCKeyGenParameterSpec(int var1, int var2, int var3) throws InvalidParameterException {
      this.m = var1;
      if (var1 < 1) {
         throw new InvalidParameterException("m must be positive");
      } else if (var1 > 32) {
         throw new InvalidParameterException(" m is too large");
      } else {
         this.n = 1 << var1;
         this.t = var2;
         if (var2 < 0) {
            throw new InvalidParameterException("t must be positive");
         } else if (var2 > this.n) {
            throw new InvalidParameterException("t must be less than n = 2^m");
         } else if (PolynomialRingGF2.degree(var3) == var1 && PolynomialRingGF2.isIrreducible(var3)) {
            this.fieldPoly = var3;
         } else {
            throw new InvalidParameterException("polynomial is not a field polynomial for GF(2^m)");
         }
      }
   }

   public int getM() {
      return this.m;
   }

   public int getN() {
      return this.n;
   }

   public int getT() {
      return this.t;
   }

   public int getFieldPoly() {
      return this.fieldPoly;
   }
}
