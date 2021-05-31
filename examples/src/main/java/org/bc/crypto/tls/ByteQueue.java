package org.bc.crypto.tls;

public class ByteQueue {
   private static final int INITBUFSIZE = 1024;
   private byte[] databuf = new byte[1024];
   private int skipped = 0;
   private int available = 0;

   public static final int nextTwoPow(int var0) {
      var0 |= var0 >> 1;
      var0 |= var0 >> 2;
      var0 |= var0 >> 4;
      var0 |= var0 >> 8;
      var0 |= var0 >> 16;
      return var0 + 1;
   }

   public void read(byte[] var1, int var2, int var3, int var4) {
      if (this.available - var4 < var3) {
         throw new TlsRuntimeException("Not enough data to read");
      } else if (var1.length - var2 < var3) {
         throw new TlsRuntimeException("Buffer size of " + var1.length + " is too small for a read of " + var3 + " bytes");
      } else {
         System.arraycopy(this.databuf, this.skipped + var4, var1, var2, var3);
      }
   }

   public void addData(byte[] var1, int var2, int var3) {
      if (this.skipped + this.available + var3 > this.databuf.length) {
         byte[] var4 = new byte[nextTwoPow(var1.length)];
         System.arraycopy(this.databuf, this.skipped, var4, 0, this.available);
         this.skipped = 0;
         this.databuf = var4;
      }

      System.arraycopy(var1, var2, this.databuf, this.skipped + this.available, var3);
      this.available += var3;
   }

   public void removeData(int var1) {
      if (var1 > this.available) {
         throw new TlsRuntimeException("Cannot remove " + var1 + " bytes, only got " + this.available);
      } else {
         this.available -= var1;
         this.skipped += var1;
         if (this.skipped > this.databuf.length / 2) {
            System.arraycopy(this.databuf, this.skipped, this.databuf, 0, this.available);
            this.skipped = 0;
         }

      }
   }

   public int size() {
      return this.available;
   }
}
