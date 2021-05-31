package org.bc.crypto.generators;

import org.bc.crypto.DataLengthException;
import org.bc.crypto.DerivationFunction;
import org.bc.crypto.DerivationParameters;
import org.bc.crypto.Digest;
import org.bc.crypto.params.ISO18033KDFParameters;
import org.bc.crypto.params.KDFParameters;

public class BaseKDFBytesGenerator implements DerivationFunction {
   private int counterStart;
   private Digest digest;
   private byte[] shared;
   private byte[] iv;

   protected BaseKDFBytesGenerator(int var1, Digest var2) {
      this.counterStart = var1;
      this.digest = var2;
   }

   public void init(DerivationParameters var1) {
      if (var1 instanceof KDFParameters) {
         KDFParameters var2 = (KDFParameters)var1;
         this.shared = var2.getSharedSecret();
         this.iv = var2.getIV();
      } else {
         if (!(var1 instanceof ISO18033KDFParameters)) {
            throw new IllegalArgumentException("KDF parameters required for KDF2Generator");
         }

         ISO18033KDFParameters var3 = (ISO18033KDFParameters)var1;
         this.shared = var3.getSeed();
         this.iv = null;
      }

   }

   public Digest getDigest() {
      return this.digest;
   }

   public int generateBytes(byte[] var1, int var2, int var3) throws DataLengthException, IllegalArgumentException {
      if (var1.length - var3 < var2) {
         throw new DataLengthException("output buffer too small");
      } else {
         long var4 = (long)var3;
         int var6 = this.digest.getDigestSize();
         if (var4 > 8589934591L) {
            throw new IllegalArgumentException("Output length too large");
         } else {
            int var7 = (int)((var4 + (long)var6 - 1L) / (long)var6);
            Object var8 = null;
            byte[] var11 = new byte[this.digest.getDigestSize()];
            int var9 = this.counterStart;

            for(int var10 = 0; var10 < var7; ++var10) {
               this.digest.update(this.shared, 0, this.shared.length);
               this.digest.update((byte)(var9 >> 24));
               this.digest.update((byte)(var9 >> 16));
               this.digest.update((byte)(var9 >> 8));
               this.digest.update((byte)var9);
               if (this.iv != null) {
                  this.digest.update(this.iv, 0, this.iv.length);
               }

               this.digest.doFinal(var11, 0);
               if (var3 > var6) {
                  System.arraycopy(var11, 0, var1, var2, var6);
                  var2 += var6;
                  var3 -= var6;
               } else {
                  System.arraycopy(var11, 0, var1, var2, var3);
               }

               ++var9;
            }

            this.digest.reset();
            return var3;
         }
      }
   }
}
