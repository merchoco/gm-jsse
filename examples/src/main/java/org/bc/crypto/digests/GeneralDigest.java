package org.bc.crypto.digests;

import org.bc.crypto.ExtendedDigest;

public abstract class GeneralDigest implements ExtendedDigest {
   private static final int BYTE_LENGTH = 64;
   private byte[] xBuf;
   private int xBufOff;
   private long byteCount;

   protected GeneralDigest() {
      this.xBuf = new byte[4];
      this.xBufOff = 0;
   }

   protected GeneralDigest(GeneralDigest var1) {
      this.xBuf = new byte[var1.xBuf.length];
      System.arraycopy(var1.xBuf, 0, this.xBuf, 0, var1.xBuf.length);
      this.xBufOff = var1.xBufOff;
      this.byteCount = var1.byteCount;
   }

   public void update(byte var1) {
      this.xBuf[this.xBufOff++] = var1;
      if (this.xBufOff == this.xBuf.length) {
         this.processWord(this.xBuf, 0);
         this.xBufOff = 0;
      }

      ++this.byteCount;
   }

   public void update(byte[] var1, int var2, int var3) {
      while(this.xBufOff != 0 && var3 > 0) {
         this.update(var1[var2]);
         ++var2;
         --var3;
      }

      while(var3 > this.xBuf.length) {
         this.processWord(var1, var2);
         var2 += this.xBuf.length;
         var3 -= this.xBuf.length;
         this.byteCount += (long)this.xBuf.length;
      }

      while(var3 > 0) {
         this.update(var1[var2]);
         ++var2;
         --var3;
      }

   }

   public void finish() {
      long var1 = this.byteCount << 3;
      this.update((byte)-128);

      while(this.xBufOff != 0) {
         this.update((byte)0);
      }

      this.processLength(var1);
      this.processBlock();
   }

   public void reset() {
      this.byteCount = 0L;
      this.xBufOff = 0;

      for(int var1 = 0; var1 < this.xBuf.length; ++var1) {
         this.xBuf[var1] = 0;
      }

   }

   public int getByteLength() {
      return 64;
   }

   protected abstract void processWord(byte[] var1, int var2);

   protected abstract void processLength(long var1);

   protected abstract void processBlock();
}
