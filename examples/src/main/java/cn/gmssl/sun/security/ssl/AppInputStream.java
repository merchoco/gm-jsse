package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.io.InputStream;

class AppInputStream extends InputStream {
   private static final byte[] SKIP_ARRAY = new byte[1024];
   private static final Debug debug = Debug.getInstance("ssl");
   private SSLSocketImpl c;
   InputRecord r = new InputRecord();
   private final byte[] oneByte = new byte[1];

   AppInputStream(SSLSocketImpl var1) {
      this.c = var1;
   }

   public int available() throws IOException {
      return !this.c.checkEOF() && this.r.isAppDataValid() ? this.r.available() : 0;
   }

   public synchronized int read() throws IOException {
      int var1 = this.read(this.oneByte, 0, 1);
      return var1 <= 0 ? -1 : this.oneByte[0] & 255;
   }

   public synchronized int read(byte[] var1, int var2, int var3) throws IOException {
      if (var1 == null) {
         throw new NullPointerException();
      } else if (var2 >= 0 && var3 >= 0 && var3 <= var1.length - var2) {
         if (var3 == 0) {
            return 0;
         } else if (this.c.checkEOF()) {
            return -1;
         } else {
            try {
               while(this.r.available() == 0) {
                  this.c.readDataRecord(this.r);
                  if (this.c.checkEOF()) {
                     return -1;
                  }
               }

               int var4 = Math.min(var3, this.r.available());
               var4 = this.r.read(var1, var2, var4);
               return var4;
            } catch (Exception var5) {
               if (debug != null && Debug.isOn("ssl")) {
                  var5.printStackTrace();
               }

               this.c.handleException(var5);
               return -1;
            }
         }
      } else {
         throw new IndexOutOfBoundsException();
      }
   }

   public synchronized long skip(long var1) throws IOException {
      long var3;
      int var6;
      for(var3 = 0L; var1 > 0L; var3 += (long)var6) {
         int var5 = (int)Math.min(var1, (long)SKIP_ARRAY.length);
         var6 = this.read(SKIP_ARRAY, 0, var5);
         if (var6 <= 0) {
            break;
         }

         var1 -= (long)var6;
      }

      return var3;
   }

   public void close() throws IOException {
      this.c.close();
   }
}
