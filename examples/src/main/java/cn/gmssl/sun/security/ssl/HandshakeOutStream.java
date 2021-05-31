package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.io.OutputStream;

public class HandshakeOutStream extends OutputStream {
   private SSLSocketImpl socket;
   private SSLEngineImpl engine;
   OutputRecord r;

   HandshakeOutStream(ProtocolVersion var1, ProtocolVersion var2, HandshakeHash var3, SSLSocketImpl var4) {
      this.socket = var4;
      this.r = new OutputRecord((byte)22);
      this.init(var1, var2, var3);
   }

   HandshakeOutStream(ProtocolVersion var1, ProtocolVersion var2, HandshakeHash var3, SSLEngineImpl var4) {
      this.engine = var4;
      this.r = new EngineOutputRecord((byte)22, var4);
      this.init(var1, var2, var3);
   }

   private void init(ProtocolVersion var1, ProtocolVersion var2, HandshakeHash var3) {
      this.r.setVersion(var1);
      this.r.setHelloVersion(var2);
      this.r.setHandshakeHash(var3);
   }

   void doHashes() {
      this.r.doHashes();
   }

   public void write(byte[] var1, int var2, int var3) throws IOException {
      while(var3 > 0) {
         int var4 = Math.min(var3, this.r.availableDataBytes());
         if (var4 == 0) {
            this.flush();
         } else {
            this.r.write(var1, var2, var4);
            var2 += var4;
            var3 -= var4;
         }
      }

   }

   public void write(int var1) throws IOException {
      if (this.r.availableDataBytes() < 1) {
         this.flush();
      }

      this.r.write(var1);
   }

   public void flush() throws IOException {
      if (this.socket != null) {
         try {
            this.socket.writeRecord(this.r);
         } catch (IOException var2) {
            this.socket.waitForClose(true);
            throw var2;
         }
      } else {
         this.engine.writeRecord((EngineOutputRecord)this.r);
      }

   }

   void setFinishedMsg() {
      assert this.socket == null;

      ((EngineOutputRecord)this.r).setFinishedMsg();
   }

   void putInt8(int var1) throws IOException {
      this.r.write(var1);
   }

   void putInt16(int var1) throws IOException {
      if (this.r.availableDataBytes() < 2) {
         this.flush();
      }

      this.r.write(var1 >> 8);
      this.r.write(var1);
   }

   void putInt24(int var1) throws IOException {
      if (this.r.availableDataBytes() < 3) {
         this.flush();
      }

      this.r.write(var1 >> 16);
      this.r.write(var1 >> 8);
      this.r.write(var1);
   }

   void putInt32(int var1) throws IOException {
      if (this.r.availableDataBytes() < 4) {
         this.flush();
      }

      this.r.write(var1 >> 24);
      this.r.write(var1 >> 16);
      this.r.write(var1 >> 8);
      this.r.write(var1);
   }

   void putBytes8(byte[] var1) throws IOException {
      if (var1 == null) {
         this.putInt8(0);
      } else {
         this.putInt8(var1.length);
         this.write(var1, 0, var1.length);
      }
   }

   public void putBytes16(byte[] var1) throws IOException {
      if (var1 == null) {
         this.putInt16(0);
      } else {
         this.putInt16(var1.length);
         this.write(var1, 0, var1.length);
      }
   }

   void putBytes24(byte[] var1) throws IOException {
      if (var1 == null) {
         this.putInt24(0);
      } else {
         this.putInt24(var1.length);
         this.write(var1, 0, var1.length);
      }
   }
}
