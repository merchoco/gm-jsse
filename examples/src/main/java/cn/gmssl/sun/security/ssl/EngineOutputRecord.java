package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

final class EngineOutputRecord extends OutputRecord {
   private EngineWriter writer;
   private boolean finishedMsg = false;

   EngineOutputRecord(byte var1, SSLEngineImpl var2) {
      super(var1, recordSize(var1));
      this.writer = var2.writer;
   }

   private static int recordSize(byte var0) {
      switch(var0) {
      case 20:
      case 21:
         return 539;
      case 22:
         return 16921;
      case 23:
         return 0;
      default:
         throw new RuntimeException("Unknown record type: " + var0);
      }
   }

   void setFinishedMsg() {
      this.finishedMsg = true;
   }

   public void flush() throws IOException {
      this.finishedMsg = false;
   }

   boolean isFinishedMsg() {
      return this.finishedMsg;
   }

   private void addMAC(MAC var1, ByteBuffer var2) throws IOException {
      if (var1.MAClen() != 0) {
         byte[] var3 = var1.compute(this.contentType(), var2);
         var2.limit(var2.limit() + var3.length);
         var2.put(var3);
      }

   }

   void encrypt(CipherBox var1, ByteBuffer var2) {
      var1.encrypt(var2);
   }

   void writeBuffer(OutputStream var1, byte[] var2, int var3, int var4) throws IOException {
      ByteBuffer var5 = (ByteBuffer)ByteBuffer.allocate(var4).put(var2, 0, var4).flip();
      this.writer.putOutboundData(var5);
   }

   void write(MAC var1, CipherBox var2) throws IOException {
      switch(this.contentType()) {
      case 20:
      case 21:
      case 22:
         if (!this.isEmpty()) {
            this.addMAC(var1);
            this.encrypt(var2);
            this.write((OutputStream)null);
         }

         return;
      default:
         throw new RuntimeException("unexpected byte buffers");
      }
   }

   void write(EngineArgs var1, MAC var2, CipherBox var3) throws IOException {
      assert this.contentType() == 23;

      if (var2 != MAC.NULL) {
         int var4 = Math.min(var1.getAppRemaining(), 16384);
         if (var4 != 0) {
            ByteBuffer var5 = var1.netData;
            int var6 = var5.position();
            int var7 = var5.limit();
            int var8 = var6 + 5;
            var5.position(var8);
            var1.gather(var4);
            var5.limit(var5.position());
            var5.position(var8);
            this.addMAC(var2, var5);
            var5.limit(var5.position());
            var5.position(var8);
            this.encrypt(var3, var5);
            if (debug != null && (Debug.isOn("record") || Debug.isOn("handshake")) && (debug != null && Debug.isOn("record") || this.contentType() == 20)) {
               System.out.println(Thread.currentThread().getName() + ", WRITE: " + this.protocolVersion + " " + InputRecord.contentName(this.contentType()) + ", length = " + var4);
            }

            int var9 = var5.limit() - var8;
            var5.put(var6, this.contentType());
            var5.put(var6 + 1, this.protocolVersion.major);
            var5.put(var6 + 2, this.protocolVersion.minor);
            var5.put(var6 + 3, (byte)(var9 >> 8));
            var5.put(var6 + 4, (byte)var9);
            var5.limit(var7);
         }
      }
   }
}
