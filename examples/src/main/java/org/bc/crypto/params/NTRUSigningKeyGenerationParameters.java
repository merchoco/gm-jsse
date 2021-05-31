package org.bc.crypto.params;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import org.bc.crypto.Digest;
import org.bc.crypto.KeyGenerationParameters;
import org.bc.crypto.digests.SHA256Digest;
import org.bc.crypto.digests.SHA512Digest;

public class NTRUSigningKeyGenerationParameters extends KeyGenerationParameters implements Cloneable {
   public static final int BASIS_TYPE_STANDARD = 0;
   public static final int BASIS_TYPE_TRANSPOSE = 1;
   public static final int KEY_GEN_ALG_RESULTANT = 0;
   public static final int KEY_GEN_ALG_FLOAT = 1;
   public static final NTRUSigningKeyGenerationParameters APR2011_439 = new NTRUSigningKeyGenerationParameters(439, 2048, 146, 1, 1, 0.165D, 400.0D, 280.0D, false, true, 0, new SHA256Digest());
   public static final NTRUSigningKeyGenerationParameters APR2011_439_PROD = new NTRUSigningKeyGenerationParameters(439, 2048, 9, 8, 5, 1, 1, 0.165D, 400.0D, 280.0D, false, true, 0, new SHA256Digest());
   public static final NTRUSigningKeyGenerationParameters APR2011_743 = new NTRUSigningKeyGenerationParameters(743, 2048, 248, 1, 1, 0.127D, 405.0D, 360.0D, true, false, 0, new SHA512Digest());
   public static final NTRUSigningKeyGenerationParameters APR2011_743_PROD = new NTRUSigningKeyGenerationParameters(743, 2048, 11, 11, 15, 1, 1, 0.127D, 405.0D, 360.0D, true, false, 0, new SHA512Digest());
   public static final NTRUSigningKeyGenerationParameters TEST157 = new NTRUSigningKeyGenerationParameters(157, 256, 29, 1, 1, 0.38D, 200.0D, 80.0D, false, false, 0, new SHA256Digest());
   public static final NTRUSigningKeyGenerationParameters TEST157_PROD = new NTRUSigningKeyGenerationParameters(157, 256, 5, 5, 8, 1, 1, 0.38D, 200.0D, 80.0D, false, false, 0, new SHA256Digest());
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
   double keyNormBound;
   public double keyNormBoundSq;
   public boolean primeCheck;
   public int basisType;
   int bitsF = 6;
   public boolean sparse;
   public int keyGenAlg;
   public Digest hashAlg;
   public int polyType;

   public NTRUSigningKeyGenerationParameters(int var1, int var2, int var3, int var4, int var5, double var6, double var8, double var10, boolean var12, boolean var13, int var14, Digest var15) {
      super(new SecureRandom(), var1);
      this.N = var1;
      this.q = var2;
      this.d = var3;
      this.B = var4;
      this.basisType = var5;
      this.beta = var6;
      this.normBound = var8;
      this.keyNormBound = var10;
      this.primeCheck = var12;
      this.sparse = var13;
      this.keyGenAlg = var14;
      this.hashAlg = var15;
      this.polyType = 0;
      this.init();
   }

   public NTRUSigningKeyGenerationParameters(int var1, int var2, int var3, int var4, int var5, int var6, int var7, double var8, double var10, double var12, boolean var14, boolean var15, int var16, Digest var17) {
      super(new SecureRandom(), var1);
      this.N = var1;
      this.q = var2;
      this.d1 = var3;
      this.d2 = var4;
      this.d3 = var5;
      this.B = var6;
      this.basisType = var7;
      this.beta = var8;
      this.normBound = var10;
      this.keyNormBound = var12;
      this.primeCheck = var14;
      this.sparse = var15;
      this.keyGenAlg = var16;
      this.hashAlg = var17;
      this.polyType = 1;
      this.init();
   }

   private void init() {
      this.betaSq = this.beta * this.beta;
      this.normBoundSq = this.normBound * this.normBound;
      this.keyNormBoundSq = this.keyNormBound * this.keyNormBound;
   }

   public NTRUSigningKeyGenerationParameters(InputStream var1) throws IOException {
      super(new SecureRandom(), 0);
      DataInputStream var2 = new DataInputStream(var1);
      this.N = var2.readInt();
      this.q = var2.readInt();
      this.d = var2.readInt();
      this.d1 = var2.readInt();
      this.d2 = var2.readInt();
      this.d3 = var2.readInt();
      this.B = var2.readInt();
      this.basisType = var2.readInt();
      this.beta = var2.readDouble();
      this.normBound = var2.readDouble();
      this.keyNormBound = var2.readDouble();
      this.signFailTolerance = var2.readInt();
      this.primeCheck = var2.readBoolean();
      this.sparse = var2.readBoolean();
      this.bitsF = var2.readInt();
      this.keyGenAlg = var2.read();
      String var3 = var2.readUTF();
      if ("SHA-512".equals(var3)) {
         this.hashAlg = new SHA512Digest();
      } else if ("SHA-256".equals(var3)) {
         this.hashAlg = new SHA256Digest();
      }

      this.polyType = var2.read();
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
      var2.writeInt(this.basisType);
      var2.writeDouble(this.beta);
      var2.writeDouble(this.normBound);
      var2.writeDouble(this.keyNormBound);
      var2.writeInt(this.signFailTolerance);
      var2.writeBoolean(this.primeCheck);
      var2.writeBoolean(this.sparse);
      var2.writeInt(this.bitsF);
      var2.write(this.keyGenAlg);
      var2.writeUTF(this.hashAlg.getAlgorithmName());
      var2.write(this.polyType);
   }

   public NTRUSigningParameters getSigningParameters() {
      return new NTRUSigningParameters(this.N, this.q, this.d, this.B, this.beta, this.normBound, this.hashAlg);
   }

   public NTRUSigningKeyGenerationParameters clone() {
      return this.polyType == 0 ? new NTRUSigningKeyGenerationParameters(this.N, this.q, this.d, this.B, this.basisType, this.beta, this.normBound, this.keyNormBound, this.primeCheck, this.sparse, this.keyGenAlg, this.hashAlg) : new NTRUSigningKeyGenerationParameters(this.N, this.q, this.d1, this.d2, this.d3, this.B, this.basisType, this.beta, this.normBound, this.keyNormBound, this.primeCheck, this.sparse, this.keyGenAlg, this.hashAlg);
   }

   public int hashCode() {
      boolean var1 = true;
      byte var2 = 1;
      int var5 = 31 * var2 + this.B;
      var5 = 31 * var5 + this.N;
      var5 = 31 * var5 + this.basisType;
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
      var5 = 31 * var5 + this.keyGenAlg;
      var3 = Double.doubleToLongBits(this.keyNormBound);
      var5 = 31 * var5 + (int)(var3 ^ var3 >>> 32);
      var3 = Double.doubleToLongBits(this.keyNormBoundSq);
      var5 = 31 * var5 + (int)(var3 ^ var3 >>> 32);
      var3 = Double.doubleToLongBits(this.normBound);
      var5 = 31 * var5 + (int)(var3 ^ var3 >>> 32);
      var3 = Double.doubleToLongBits(this.normBoundSq);
      var5 = 31 * var5 + (int)(var3 ^ var3 >>> 32);
      var5 = 31 * var5 + this.polyType;
      var5 = 31 * var5 + (this.primeCheck ? 1231 : 1237);
      var5 = 31 * var5 + this.q;
      var5 = 31 * var5 + this.signFailTolerance;
      var5 = 31 * var5 + (this.sparse ? 1231 : 1237);
      return var5;
   }

   public boolean equals(Object var1) {
      if (this == var1) {
         return true;
      } else if (var1 == null) {
         return false;
      } else if (!(var1 instanceof NTRUSigningKeyGenerationParameters)) {
         return false;
      } else {
         NTRUSigningKeyGenerationParameters var2 = (NTRUSigningKeyGenerationParameters)var1;
         if (this.B != var2.B) {
            return false;
         } else if (this.N != var2.N) {
            return false;
         } else if (this.basisType != var2.basisType) {
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

            if (this.keyGenAlg != var2.keyGenAlg) {
               return false;
            } else if (Double.doubleToLongBits(this.keyNormBound) != Double.doubleToLongBits(var2.keyNormBound)) {
               return false;
            } else if (Double.doubleToLongBits(this.keyNormBoundSq) != Double.doubleToLongBits(var2.keyNormBoundSq)) {
               return false;
            } else if (Double.doubleToLongBits(this.normBound) != Double.doubleToLongBits(var2.normBound)) {
               return false;
            } else if (Double.doubleToLongBits(this.normBoundSq) != Double.doubleToLongBits(var2.normBoundSq)) {
               return false;
            } else if (this.polyType != var2.polyType) {
               return false;
            } else if (this.primeCheck != var2.primeCheck) {
               return false;
            } else if (this.q != var2.q) {
               return false;
            } else if (this.signFailTolerance != var2.signFailTolerance) {
               return false;
            } else {
               return this.sparse == var2.sparse;
            }
         }
      }
   }

   public String toString() {
      DecimalFormat var1 = new DecimalFormat("0.00");
      StringBuilder var2 = new StringBuilder("SignatureParameters(N=" + this.N + " q=" + this.q);
      if (this.polyType == 0) {
         var2.append(" polyType=SIMPLE d=" + this.d);
      } else {
         var2.append(" polyType=PRODUCT d1=" + this.d1 + " d2=" + this.d2 + " d3=" + this.d3);
      }

      var2.append(" B=" + this.B + " basisType=" + this.basisType + " beta=" + var1.format(this.beta) + " normBound=" + var1.format(this.normBound) + " keyNormBound=" + var1.format(this.keyNormBound) + " prime=" + this.primeCheck + " sparse=" + this.sparse + " keyGenAlg=" + this.keyGenAlg + " hashAlg=" + this.hashAlg + ")");
      return var2.toString();
   }
}
