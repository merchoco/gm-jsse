package org.bc.crypto.params;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.DecimalFormat;
import org.bc.crypto.Digest;
import org.bc.crypto.digests.SHA256Digest;
import org.bc.crypto.digests.SHA512Digest;

public class NTRUSigningParameters implements Cloneable {
   public int N;
   public int q;
   public int d;
   public int d1;
   public int d2;
   public int d3;
   public int B;
   double beta;
   public double betaSq;
   double normBound;
   public double normBoundSq;
   public int signFailTolerance = 100;
   int bitsF = 6;
   public Digest hashAlg;

   public NTRUSigningParameters(int var1, int var2, int var3, int var4, double var5, double var7, Digest var9) {
      this.N = var1;
      this.q = var2;
      this.d = var3;
      this.B = var4;
      this.beta = var5;
      this.normBound = var7;
      this.hashAlg = var9;
      this.init();
   }

   public NTRUSigningParameters(int var1, int var2, int var3, int var4, int var5, int var6, double var7, double var9, double var11, Digest var13) {
      this.N = var1;
      this.q = var2;
      this.d1 = var3;
      this.d2 = var4;
      this.d3 = var5;
      this.B = var6;
      this.beta = var7;
      this.normBound = var9;
      this.hashAlg = var13;
      this.init();
   }

   private void init() {
      this.betaSq = this.beta * this.beta;
      this.normBoundSq = this.normBound * this.normBound;
   }

   public NTRUSigningParameters(InputStream var1) throws IOException {
      DataInputStream var2 = new DataInputStream(var1);
      this.N = var2.readInt();
      this.q = var2.readInt();
      this.d = var2.readInt();
      this.d1 = var2.readInt();
      this.d2 = var2.readInt();
      this.d3 = var2.readInt();
      this.B = var2.readInt();
      this.beta = var2.readDouble();
      this.normBound = var2.readDouble();
      this.signFailTolerance = var2.readInt();
      this.bitsF = var2.readInt();
      String var3 = var2.readUTF();
      if ("SHA-512".equals(var3)) {
         this.hashAlg = new SHA512Digest();
      } else if ("SHA-256".equals(var3)) {
         this.hashAlg = new SHA256Digest();
      }

      this.init();
   }

   public void writeTo(OutputStream var1) throws IOException {
      DataOutputStream var2 = new DataOutputStream(var1);
      var2.writeInt(this.N);
      var2.writeInt(this.q);
      var2.writeInt(this.d);
      var2.writeInt(this.d1);
      var2.writeInt(this.d2);
      var2.writeInt(this.d3);
      var2.writeInt(this.B);
      var2.writeDouble(this.beta);
      var2.writeDouble(this.normBound);
      var2.writeInt(this.signFailTolerance);
      var2.writeInt(this.bitsF);
      var2.writeUTF(this.hashAlg.getAlgorithmName());
   }

   public NTRUSigningParameters clone() {
      return new NTRUSigningParameters(this.N, this.q, this.d, this.B, this.beta, this.normBound, this.hashAlg);
   }

   public int hashCode() {
      boolean var1 = true;
      byte var2 = 1;
      int var5 = 31 * var2 + this.B;
      var5 = 31 * var5 + this.N;
      long var3 = Double.doubleToLongBits(this.beta);
      var5 = 31 * var5 + (int)(var3 ^ var3 >>> 32);
      var3 = Double.doubleToLongBits(this.betaSq);
      var5 = 31 * var5 + (int)(var3 ^ var3 >>> 32);
      var5 = 31 * var5 + this.bitsF;
      var5 = 31 * var5 + this.d;
      var5 = 31 * var5 + this.d1;
      var5 = 31 * var5 + this.d2;
      var5 = 31 * var5 + this.d3;
      var5 = 31 * var5 + (this.hashAlg == null ? 0 : this.hashAlg.getAlgorithmName().hashCode());
      var3 = Double.doubleToLongBits(this.normBound);
      var5 = 31 * var5 + (int)(var3 ^ var3 >>> 32);
      var3 = Double.doubleToLongBits(this.normBoundSq);
      var5 = 31 * var5 + (int)(var3 ^ var3 >>> 32);
      var5 = 31 * var5 + this.q;
      var5 = 31 * var5 + this.signFailTolerance;
      return var5;
   }

   public boolean equals(Object var1) {
      if (this == var1) {
         return true;
      } else if (var1 == null) {
         return false;
      } else if (!(var1 instanceof NTRUSigningParameters)) {
         return false;
      } else {
         NTRUSigningParameters var2 = (NTRUSigningParameters)var1;
         if (this.B != var2.B) {
            return false;
         } else if (this.N != var2.N) {
            return false;
         } else if (Double.doubleToLongBits(this.beta) != Double.doubleToLongBits(var2.beta)) {
            return false;
         } else if (Double.doubleToLongBits(this.betaSq) != Double.doubleToLongBits(var2.betaSq)) {
            return false;
         } else if (this.bitsF != var2.bitsF) {
            return false;
         } else if (this.d != var2.d) {
            return false;
         } else if (this.d1 != var2.d1) {
            return false;
         } else if (this.d2 != var2.d2) {
            return false;
         } else if (this.d3 != var2.d3) {
            return false;
         } else {
            if (this.hashAlg == null) {
               if (var2.hashAlg != null) {
                  return false;
               }
            } else if (!this.hashAlg.getAlgorithmName().equals(var2.hashAlg.getAlgorithmName())) {
               return false;
            }

            if (Double.doubleToLongBits(this.normBound) != Double.doubleToLongBits(var2.normBound)) {
               return false;
            } else if (Double.doubleToLongBits(this.normBoundSq) != Double.doubleToLongBits(var2.normBoundSq)) {
               return false;
            } else if (this.q != var2.q) {
               return false;
            } else {
               return this.signFailTolerance == var2.signFailTolerance;
            }
         }
      }
   }

   public String toString() {
      DecimalFormat var1 = new DecimalFormat("0.00");
      StringBuilder var2 = new StringBuilder("SignatureParameters(N=" + this.N + " q=" + this.q);
      var2.append(" B=" + this.B + " beta=" + var1.format(this.beta) + " normBound=" + var1.format(this.normBound) + " hashAlg=" + this.hashAlg + ")");
      return var2.toString();
   }
}
