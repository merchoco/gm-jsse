package org.bc.crypto.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bc.crypto.BufferedBlockCipher;
import org.bc.crypto.StreamCipher;

public class CipherInputStream extends FilterInputStream {
   private BufferedBlockCipher bufferedBlockCipher;
   private StreamCipher streamCipher;
   private byte[] buf;
   private byte[] inBuf;
   private int bufOff;
   private int maxBuf;
   private boolean finalized;
   private static final int INPUT_BUF_SIZE = 2048;

   public CipherInputStream(InputStream var1, BufferedBlockCipher var2) {
      super(var1);
      this.bufferedBlockCipher = var2;
      this.buf = new byte[var2.getOutputSize(2048)];
      this.inBuf = new byte[2048];
   }

   public CipherInputStream(InputStream var1, StreamCipher var2) {
      super(var1);
      this.streamCipher = var2;
      this.buf = new byte[2048];
      this.inBuf = new byte[2048];
   }

   private int nextChunk() throws IOException {
      int var1 = super.available();
      if (var1 <= 0) {
         var1 = 1;
      }

      if (var1 > this.inBuf.length) {
         var1 = super.read(this.inBuf, 0, this.inBuf.length);
      } else {
         var1 = super.read(this.inBuf, 0, var1);
      }

      if (var1 < 0) {
         if (this.finalized) {
            return -1;
         }

         try {
            if (this.bufferedBlockCipher != null) {
               this.maxBuf = this.bufferedBlockCipher.doFinal(this.buf, 0);
            } else {
               this.maxBuf = 0;
            }
         } catch (Exception var4) {
            throw new IOException("error processing stream: " + var4.toString());
         }

         this.bufOff = 0;
         this.finalized = true;
         if (this.bufOff == this.maxBuf) {
            return -1;
         }
      } else {
         this.bufOff = 0;

         try {
            if (this.bufferedBlockCipher != null) {
               this.maxBuf = this.bufferedBlockCipher.processBytes(this.inBuf, 0, var1, this.buf, 0);
            } else {
               this.streamCipher.processBytes(this.inBuf, 0, var1, this.buf, 0);
               this.maxBuf = var1;
            }
         } catch (Exception var3) {
            throw new IOException("error processing stream: " + var3.toString());
         }

         if (this.maxBuf == 0) {
            return this.nextChunk();
         }
      }

      return this.maxBuf;
   }

   public int read() throws IOException {
      return this.bufOff == this.maxBuf && this.nextChunk() < 0 ? -1 : this.buf[this.bufOff++] & 255;
   }

   public int read(byte[] var1) throws IOException {
      return this.read(var1, 0, var1.length);
   }

   public int read(byte[] var1, int var2, int var3) throws IOException {
      if (this.bufOff == this.maxBuf && this.nextChunk() < 0) {
         return -1;
      } else {
         int var4 = this.maxBuf - this.bufOff;
         if (var3 > var4) {
            System.arraycopy(this.buf, this.bufOff, var1, var2, var4);
            this.bufOff = this.maxBuf;
            return var4;
         } else {
            System.arraycopy(this.buf, this.bufOff, var1, var2, var3);
            this.bufOff += var3;
            return var3;
         }
      }
   }

   public long skip(long var1) throws IOException {
      if (var1 <= 0L) {
         return 0L;
      } else {
         int var3 = this.maxBuf - this.bufOff;
         if (var1 > (long)var3) {
            this.bufOff = this.maxBuf;
            return (long)var3;
         } else {
            this.bufOff += (int)var1;
            return (long)((int)var1);
         }
      }
   }

   public int available() throws IOException {
      return this.maxBuf - this.bufOff;
   }

   public void close() throws IOException {
      super.close();
   }

   public boolean markSupported() {
      return false;
   }
}
