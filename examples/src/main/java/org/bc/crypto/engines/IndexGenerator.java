package org.bc.crypto.engines;

import org.bc.crypto.Digest;
import org.bc.crypto.params.NTRUEncryptionParameters;
import org.bc.util.Arrays;

public class IndexGenerator {
   private byte[] seed;
   private int N;
   private int c;
   private int minCallsR;
   private int totLen;
   private int remLen;
   private IndexGenerator.BitString buf;
   private int counter;
   private boolean initialized;
   private Digest hashAlg;
   private int hLen;

   IndexGenerator(byte[] var1, NTRUEncryptionParameters var2) {
      this.seed = var1;
      this.N = var2.N;
      this.c = var2.c;
      this.minCallsR = var2.minCallsR;
      this.totLen = 0;
      this.remLen = 0;
      this.counter = 0;
      this.hashAlg = var2.hashAlg;
      this.hLen = this.hashAlg.getDigestSize();
      this.initialized = false;
   }

   int nextIndex() {
      if (!this.initialized) {
         this.buf = new IndexGenerator.BitString();

         for(byte[] var1 = new byte[this.hashAlg.getDigestSize()]; this.counter < this.minCallsR; ++this.counter) {
            this.appendHash(this.buf, var1);
         }

         this.totLen = this.minCallsR * 8 * this.hLen;
         this.remLen = this.totLen;
         this.initialized = true;
      }

      int var2;
      do {
         this.totLen += this.c;
         IndexGenerator.BitString var5 = this.buf.getTrailing(this.remLen);
         if (this.remLen >= this.c) {
            this.remLen -= this.c;
         } else {
            var2 = this.c - this.remLen;
            int var3 = this.counter + (var2 + this.hLen - 1) / this.hLen;
            byte[] var4 = new byte[this.hashAlg.getDigestSize()];

            while(this.counter < var3) {
               this.appendHash(var5, var4);
               ++this.counter;
               if (var2 > 8 * this.hLen) {
                  var2 -= 8 * this.hLen;
               }
            }

            this.remLen = 8 * this.hLen - var2;
            this.buf = new IndexGenerator.BitString();
            this.buf.appendBits(var4);
         }

         var2 = var5.getLeadingAsInt(this.c);
      } while(var2 >= (1 << this.c) - (1 << this.c) % this.N);

      return var2 % this.N;
   }

   private void appendHash(IndexGenerator.BitString var1, byte[] var2) {
      this.hashAlg.update(this.seed, 0, this.seed.length);
      this.putInt(this.hashAlg, this.counter);
      this.hashAlg.doFinal(var2, 0);
      var1.appendBits(var2);
   }

   private void putInt(Digest var1, int var2) {
      var1.update((byte)(var2 >> 24));
      var1.update((byte)(var2 >> 16));
      var1.update((byte)(var2 >> 8));
      var1.update((byte)var2);
   }

   private static byte[] copyOf(byte[] var0, int var1) {
      byte[] var2 = new byte[var1];
      System.arraycopy(var0, 0, var2, 0, var1 < var0.length ? var1 : var0.length);
      return var2;
   }

   public static class BitString {
      byte[] bytes = new byte[4];
      int numBytes;
      int lastByteBits;

      void appendBits(byte[] var1) {
         for(int var2 = 0; var2 != var1.length; ++var2) {
            this.appendBits(var1[var2]);
         }

      }

      public void appendBits(byte var1) {
         if (this.numBytes == this.bytes.length) {
            this.bytes = IndexGenerator.copyOf(this.bytes, 2 * this.bytes.length);
         }

         if (this.numBytes == 0) {
            this.numBytes = 1;
            this.bytes[0] = var1;
            this.lastByteBits = 8;
         } else if (this.lastByteBits == 8) {
            this.bytes[this.numBytes++] = var1;
         } else {
            int var2 = 8 - this.lastByteBits;
            this.bytes[this.numBytes - 1] = (byte)(this.bytes[this.numBytes - 1] | (var1 & 255) << this.lastByteBits);
            this.bytes[this.numBytes++] = (byte)((var1 & 255) >> var2);
         }

      }

      public IndexGenerator.BitString getTrailing(int var1) {
         IndexGenerator.BitString var2 = new IndexGenerator.BitString();
         var2.numBytes = (var1 + 7) / 8;
         var2.bytes = new byte[var2.numBytes];

         int var3;
         for(var3 = 0; var3 < var2.numBytes; ++var3) {
            var2.bytes[var3] = this.bytes[var3];
         }

         var2.lastByteBits = var1 % 8;
         if (var2.lastByteBits == 0) {
            var2.lastByteBits = 8;
         } else {
            var3 = 32 - var2.lastByteBits;
            var2.bytes[var2.numBytes - 1] = (byte)(var2.bytes[var2.numBytes - 1] << var3 >>> var3);
         }

         return var2;
      }

      public int getLeadingAsInt(int var1) {
         int var2 = (this.numBytes - 1) * 8 + this.lastByteBits - var1;
         int var3 = var2 / 8;
         int var4 = var2 % 8;
         int var5 = (this.bytes[var3] & 255) >>> var4;
         int var6 = 8 - var4;

         for(int var7 = var3 + 1; var7 < this.numBytes; ++var7) {
            var5 |= (this.bytes[var7] & 255) << var6;
            var6 += 8;
         }

         return var5;
      }

      public byte[] getBytes() {
         return Arrays.clone(this.bytes);
      }
   }
}
