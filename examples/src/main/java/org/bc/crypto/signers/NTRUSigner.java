package org.bc.crypto.signers;

import java.nio.ByteBuffer;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.Digest;
import org.bc.crypto.params.NTRUSigningParameters;
import org.bc.crypto.params.NTRUSigningPrivateKeyParameters;
import org.bc.crypto.params.NTRUSigningPublicKeyParameters;
import org.bc.math.ntru.polynomial.IntegerPolynomial;
import org.bc.math.ntru.polynomial.Polynomial;

public class NTRUSigner {
   private NTRUSigningParameters params;
   private Digest hashAlg;
   private NTRUSigningPrivateKeyParameters signingKeyPair;
   private NTRUSigningPublicKeyParameters verificationKey;

   public NTRUSigner(NTRUSigningParameters var1) {
      this.params = var1;
   }

   public void init(boolean var1, CipherParameters var2) {
      if (var1) {
         this.signingKeyPair = (NTRUSigningPrivateKeyParameters)var2;
      } else {
         this.verificationKey = (NTRUSigningPublicKeyParameters)var2;
      }

      this.hashAlg = this.params.hashAlg;
      this.hashAlg.reset();
   }

   public void update(byte var1) {
      if (this.hashAlg == null) {
         throw new IllegalStateException("Call initSign or initVerify first!");
      } else {
         this.hashAlg.update(var1);
      }
   }

   public void update(byte[] var1, int var2, int var3) {
      if (this.hashAlg == null) {
         throw new IllegalStateException("Call initSign or initVerify first!");
      } else {
         this.hashAlg.update(var1, var2, var3);
      }
   }

   public byte[] generateSignature() {
      if (this.hashAlg != null && this.signingKeyPair != null) {
         byte[] var1 = new byte[this.hashAlg.getDigestSize()];
         this.hashAlg.doFinal(var1, 0);
         return this.signHash(var1, this.signingKeyPair);
      } else {
         throw new IllegalStateException("Call initSign first!");
      }
   }

   private byte[] signHash(byte[] var1, NTRUSigningPrivateKeyParameters var2) {
      int var3 = 0;
      NTRUSigningPublicKeyParameters var6 = var2.getPublicKey();

      IntegerPolynomial var4;
      IntegerPolynomial var5;
      do {
         ++var3;
         if (var3 > this.params.signFailTolerance) {
            throw new IllegalStateException("Signing failed: too many retries (max=" + this.params.signFailTolerance + ")");
         }

         var5 = this.createMsgRep(var1, var3);
         var4 = this.sign(var5, var2);
      } while(!this.verify(var5, var4, var6.h));

      byte[] var7 = var4.toBinary(this.params.q);
      ByteBuffer var8 = ByteBuffer.allocate(var7.length + 4);
      var8.put(var7);
      var8.putInt(var3);
      return var8.array();
   }

   private IntegerPolynomial sign(IntegerPolynomial var1, NTRUSigningPrivateKeyParameters var2) {
      int var3 = this.params.N;
      int var4 = this.params.q;
      int var5 = this.params.B;
      NTRUSigningPrivateKeyParameters var6 = var2;
      NTRUSigningPublicKeyParameters var7 = var2.getPublicKey();
      IntegerPolynomial var8 = new IntegerPolynomial(var3);

      Polynomial var10;
      Polynomial var11;
      IntegerPolynomial var12;
      IntegerPolynomial var13;
      for(int var9 = var5; var9 >= 1; --var9) {
         var10 = var6.getBasis(var9).f;
         var11 = var6.getBasis(var9).fPrime;
         var12 = var10.mult(var1);
         var12.div(var4);
         var12 = var11.mult(var12);
         var13 = var11.mult(var1);
         var13.div(var4);
         var13 = var10.mult(var13);
         var12.sub(var13);
         var8.add(var12);
         IntegerPolynomial var15 = (IntegerPolynomial)var6.getBasis(var9).h.clone();
         if (var9 > 1) {
            var15.sub(var6.getBasis(var9 - 1).h);
         } else {
            var15.sub(var7.h);
         }

         var1 = var12.mult(var15, var4);
      }

      var10 = var6.getBasis(0).f;
      var11 = var6.getBasis(0).fPrime;
      var12 = var10.mult(var1);
      var12.div(var4);
      var12 = var11.mult(var12);
      var13 = var11.mult(var1);
      var13.div(var4);
      var13 = var10.mult(var13);
      var12.sub(var13);
      var8.add(var12);
      var8.modPositive(var4);
      return var8;
   }

   public boolean verifySignature(byte[] var1) {
      if (this.hashAlg != null && this.verificationKey != null) {
         byte[] var2 = new byte[this.hashAlg.getDigestSize()];
         this.hashAlg.doFinal(var2, 0);
         return this.verifyHash(var2, var1, this.verificationKey);
      } else {
         throw new IllegalStateException("Call initVerify first!");
      }
   }

   private boolean verifyHash(byte[] var1, byte[] var2, NTRUSigningPublicKeyParameters var3) {
      ByteBuffer var4 = ByteBuffer.wrap(var2);
      byte[] var5 = new byte[var2.length - 4];
      var4.get(var5);
      IntegerPolynomial var6 = IntegerPolynomial.fromBinary(var5, this.params.N, this.params.q);
      int var7 = var4.getInt();
      return this.verify(this.createMsgRep(var1, var7), var6, var3.h);
   }

   private boolean verify(IntegerPolynomial var1, IntegerPolynomial var2, IntegerPolynomial var3) {
      int var4 = this.params.q;
      double var5 = this.params.normBoundSq;
      double var7 = this.params.betaSq;
      IntegerPolynomial var9 = var3.mult(var2, var4);
      var9.sub(var1);
      long var10 = (long)((double)var2.centeredNormSq(var4) + var7 * (double)var9.centeredNormSq(var4));
      return (double)var10 <= var5;
   }

   protected IntegerPolynomial createMsgRep(byte[] var1, int var2) {
      int var3 = this.params.N;
      int var4 = this.params.q;
      int var5 = 31 - Integer.numberOfLeadingZeros(var4);
      int var6 = (var5 + 7) / 8;
      IntegerPolynomial var7 = new IntegerPolynomial(var3);
      ByteBuffer var8 = ByteBuffer.allocate(var1.length + 4);
      var8.put(var1);
      var8.putInt(var2);
      NTRUSignerPrng var9 = new NTRUSignerPrng(var8.array(), this.params.hashAlg);

      for(int var10 = 0; var10 < var3; ++var10) {
         byte[] var11 = var9.nextBytes(var6);
         byte var12 = var11[var11.length - 1];
         int var14 = var12 >> 8 * var6 - var5;
         var14 <<= 8 * var6 - var5;
         var11[var11.length - 1] = (byte)var14;
         ByteBuffer var13 = ByteBuffer.allocate(4);
         var13.put(var11);
         var13.rewind();
         var7.coeffs[var10] = Integer.reverseBytes(var13.getInt());
      }

      return var7;
   }
}
