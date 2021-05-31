package org.bc.crypto.io;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.bc.crypto.BufferedBlockCipher;
import org.bc.crypto.StreamCipher;

public class CipherOutputStream extends FilterOutputStream {
   private BufferedBlockCipher bufferedBlockCipher;
   private StreamCipher streamCipher;
   private byte[] oneByte = new byte[1];
   private byte[] buf;

   public CipherOutputStream(OutputStream var1, BufferedBlockCipher var2) {
      super(var1);
      this.bufferedBlockCipher = var2;
      this.buf = new byte[var2.getBlockSize()];
   }

   public CipherOutputStream(OutputStream var1, StreamCipher var2) {
      super(var1);
      this.streamCipher = var2;
   }

   public void write(int var1) throws IOException {
      this.oneByte[0] = (byte)var1;
      if (this.bufferedBlockCipher != null) {
         int var2 = this.bufferedBlockCipher.processBytes(this.oneByte, 0, 1, this.buf, 0);
         if (var2 != 0) {
            this.out.write(this.buf, 0, var2);
         }
      } else {
         this.out.write(this.streamCipher.returnByte((byte)var1));
      }

   }

   public void write(byte[] var1) throws IOException {
      this.write(var1, 0, var1.length);
   }

   public void write(byte[] var1, int var2, int var3) throws IOException {
      byte[] var4;
      if (this.bufferedBlockCipher != null) {
         var4 = new byte[this.bufferedBlockCipher.getOutputSize(var3)];
         int var5 = this.bufferedBlockCipher.processBytes(var1, var2, var3, var4, 0);
         if (var5 != 0) {
            this.out.write(var4, 0, var5);
         }
      } else {
         var4 = new byte[var3];
         this.streamCipher.processBytes(var1, var2, var3, var4, 0);
         this.out.write(var4, 0, var3);
      }

   }

   public void flush() throws IOException {
      super.flush();
   }

   public void close() throws IOException {
      try {
         if (this.bufferedBlockCipher != null) {
            byte[] var1 = new byte[this.bufferedBlockCipher.getOutputSize(0)];
            int var2 = this.bufferedBlockCipher.doFinal(var1, 0);
            if (var2 != 0) {
               this.out.write(var1, 0, var2);
            }
         }
      } catch (Exception var3) {
         throw new IOException("Error closing stream: " + var3.toString());
      }

      this.flush();
      super.close();
   }
}
