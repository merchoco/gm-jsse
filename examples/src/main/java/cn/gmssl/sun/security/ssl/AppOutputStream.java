package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.io.OutputStream;

class AppOutputStream extends OutputStream {
   private SSLSocketImpl c;
   OutputRecord r = new OutputRecord((byte)23);
   private final byte[] oneByte = new byte[1];

   AppOutputStream(SSLSocketImpl var1) {
      this.c = var1;
   }

   public synchronized void write(byte[] var1, int var2, int var3) throws IOException {
      if (var1 == null) {
         throw new NullPointerException();
      } else if (var2 >= 0 && var3 >= 0 && var3 <= var1.length - var2) {
         if (var3 != 0) {
            this.c.checkWrite();

            try {
               do {
                  int var4 = Math.min(var3, this.r.availableDataBytes());
                  if (var4 > 0) {
                     this.r.write(var1, var2, var4);
                     var2 += var4;
                     var3 -= var4;
                  }

                  this.c.writeRecord(this.r);
                  this.c.checkWrite();
               } while(var3 > 0);
            } catch (Exception var5) {
               this.c.handleException(var5);
            }

         }
      } else {
         throw new IndexOutOfBoundsException();
      }
   }

   public synchronized void write(int var1) throws IOException {
      this.oneByte[0] = (byte)var1;
      this.write(this.oneByte, 0, 1);
   }

   public void close() throws IOException {
      this.c.close();
   }
}
