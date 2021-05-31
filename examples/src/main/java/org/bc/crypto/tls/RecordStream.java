package org.bc.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bc.crypto.Digest;

class RecordStream {
   private TlsProtocolHandler handler;
   private InputStream is;
   private OutputStream os;
   private TlsCompression readCompression = null;
   private TlsCompression writeCompression = null;
   private TlsCipher readCipher = null;
   private TlsCipher writeCipher = null;
   private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
   private TlsClientContext context = null;
   private CombinedHash hash = null;

   RecordStream(TlsProtocolHandler var1, InputStream var2, OutputStream var3) {
      this.handler = var1;
      this.is = var2;
      this.os = var3;
      this.readCompression = new TlsNullCompression();
      this.writeCompression = this.readCompression;
      this.readCipher = new TlsNullCipher();
      this.writeCipher = this.readCipher;
   }

   void init(TlsClientContext var1) {
      this.context = var1;
      this.hash = new CombinedHash(var1);
   }

   void clientCipherSpecDecided(TlsCompression var1, TlsCipher var2) {
      this.writeCompression = var1;
      this.writeCipher = var2;
   }

   void serverClientSpecReceived() {
      this.readCompression = this.writeCompression;
      this.readCipher = this.writeCipher;
   }

   public void readData() throws IOException {
      short var1 = TlsUtils.readUint8(this.is);
      ProtocolVersion var2 = ProtocolVersion.TLSv10;
      if (!var2.equals(TlsUtils.readVersion(this.is))) {
         throw new TlsFatalAlert((short)47);
      } else {
         int var3 = TlsUtils.readUint16(this.is);
         byte[] var4 = this.decodeAndVerify(var1, this.is, var3);
         this.handler.processData(var1, var4, 0, var4.length);
      }
   }

   protected byte[] decodeAndVerify(short var1, InputStream var2, int var3) throws IOException {
      byte[] var4 = new byte[var3];
      TlsUtils.readFully(var4, var2);
      byte[] var5 = this.readCipher.decodeCiphertext(var1, var4, 0, var4.length);
      OutputStream var6 = this.readCompression.decompress(this.buffer);
      if (var6 == this.buffer) {
         return var5;
      } else {
         var6.write(var5, 0, var5.length);
         var6.flush();
         return this.getBufferContents();
      }
   }

   protected void writeMessage(short var1, byte[] var2, int var3, int var4) throws IOException {
      if (var1 == 22) {
         this.updateHandshakeData(var2, var3, var4);
      }

      OutputStream var5 = this.writeCompression.compress(this.buffer);
      byte[] var6;
      byte[] var7;
      if (var5 == this.buffer) {
         var6 = this.writeCipher.encodePlaintext(var1, var2, var3, var4);
      } else {
         var5.write(var2, var3, var4);
         var5.flush();
         var7 = this.getBufferContents();
         var6 = this.writeCipher.encodePlaintext(var1, var7, 0, var7.length);
      }

      var7 = new byte[var6.length + 5];
      TlsUtils.writeUint8(var1, var7, 0);
      TlsUtils.writeVersion(ProtocolVersion.TLSv10, var7, 1);
      TlsUtils.writeUint16(var6.length, var7, 3);
      System.arraycopy(var6, 0, var7, 5, var6.length);
      this.os.write(var7);
      this.os.flush();
   }

   void updateHandshakeData(byte[] var1, int var2, int var3) {
      this.hash.update(var1, var2, var3);
   }

   byte[] getCurrentHash(byte[] var1) {
      CombinedHash var2 = new CombinedHash(this.hash);
      boolean var3 = this.context.getServerVersion().getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
      if (!var3 && var1 != null) {
         var2.update(var1, 0, var1.length);
      }

      return doFinal(var2);
   }

   protected void close() throws IOException {
      IOException var1 = null;

      try {
         this.is.close();
      } catch (IOException var4) {
         var1 = var4;
      }

      try {
         this.os.close();
      } catch (IOException var3) {
         var1 = var3;
      }

      if (var1 != null) {
         throw var1;
      }
   }

   protected void flush() throws IOException {
      this.os.flush();
   }

   private byte[] getBufferContents() {
      byte[] var1 = this.buffer.toByteArray();
      this.buffer.reset();
      return var1;
   }

   private static byte[] doFinal(Digest var0) {
      byte[] var1 = new byte[var0.getDigestSize()];
      var0.doFinal(var1, 0);
      return var1;
   }
}
