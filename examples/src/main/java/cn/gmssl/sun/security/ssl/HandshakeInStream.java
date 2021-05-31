package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.io.InputStream;
import javax.net.ssl.SSLException;

public class HandshakeInStream extends InputStream {
   InputRecord r = new InputRecord();

   HandshakeInStream(HandshakeHash var1) {
      this.r.setHandshakeHash(var1);
   }

   public int available() {
      return this.r.available();
   }

   public int read() throws IOException {
      int var1 = this.r.read();
      if (var1 == -1) {
         throw new SSLException("Unexpected end of handshake data");
      } else {
         return var1;
      }
   }

   public int read(byte[] var1, int var2, int var3) throws IOException {
      int var4 = this.r.read(var1, var2, var3);
      if (var4 != var3) {
         throw new SSLException("Unexpected end of handshake data");
      } else {
         return var4;
      }
   }

   public long skip(long var1) throws IOException {
      return this.r.skip(var1);
   }

   public void mark(int var1) {
      this.r.mark(var1);
   }

   public void reset() {
      this.r.reset();
   }

   public boolean markSupported() {
      return true;
   }

   void incomingRecord(InputRecord var1) throws IOException {
      this.r.queueHandshake(var1);
   }

   void digestNow() {
      this.r.doHashes();
   }

   void ignore(int var1) {
      this.r.ignore(var1);
   }

   int getInt8() throws IOException {
      return this.read();
   }

   int getInt16() throws IOException {
      return this.getInt8() << 8 | this.getInt8();
   }

   int getInt24() throws IOException {
      return this.getInt8() << 16 | this.getInt8() << 8 | this.getInt8();
   }

   int getInt32() throws IOException {
      return this.getInt8() << 24 | this.getInt8() << 16 | this.getInt8() << 8 | this.getInt8();
   }

   byte[] getBytes8() throws IOException {
      int var1 = this.getInt8();
      byte[] var2 = new byte[var1];
      this.read(var2, 0, var1);
      return var2;
   }

   public byte[] getBytes16() throws IOException {
      int var1 = this.getInt16();
      byte[] var2 = new byte[var1];
      this.read(var2, 0, var1);
      return var2;
   }

   byte[] getBytes24() throws IOException {
      int var1 = this.getInt24();
      byte[] var2 = new byte[var1];
      this.read(var2, 0, var1);
      return var2;
   }
}
