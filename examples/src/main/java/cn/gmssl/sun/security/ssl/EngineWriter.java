package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import sun.misc.HexDumpEncoder;

final class EngineWriter {
   private LinkedList<Object> outboundList = new LinkedList();
   private boolean outboundClosed = false;
   private static final Debug debug = Debug.getInstance("ssl");

   private HandshakeStatus getOutboundData(ByteBuffer var1) {
      Object var2 = this.outboundList.removeFirst();

      assert var2 instanceof ByteBuffer;

      ByteBuffer var3 = (ByteBuffer)var2;

      assert var1.remaining() >= var3.remaining();

      var1.put(var3);
      if (this.hasOutboundDataInternal()) {
         var2 = this.outboundList.getFirst();
         if (var2 == HandshakeStatus.FINISHED) {
            this.outboundList.removeFirst();
            return HandshakeStatus.FINISHED;
         } else {
            return HandshakeStatus.NEED_WRAP;
         }
      } else {
         return null;
      }
   }

   synchronized void writeRecord(EngineOutputRecord var1, MAC var2, CipherBox var3) throws IOException {
      if (this.outboundClosed) {
         throw new IOException("writer side was already closed.");
      } else {
         var1.write(var2, var3);
         if (var1.isFinishedMsg()) {
            this.outboundList.addLast(HandshakeStatus.FINISHED);
         }

      }
   }

   private void dumpPacket(EngineArgs var1, boolean var2) {
      try {
         HexDumpEncoder var3 = new HexDumpEncoder();
         ByteBuffer var4 = var1.netData.duplicate();
         int var5 = var4.position();
         var4.position(var5 - var1.deltaNet());
         var4.limit(var5);
         System.out.println("[Raw write" + (var2 ? "" : " (bb)") + "]: length = " + var4.remaining());
         var3.encodeBuffer(var4, System.out);
      } catch (IOException var6) {
         ;
      }

   }

   synchronized HandshakeStatus writeRecord(EngineOutputRecord var1, EngineArgs var2, MAC var3, CipherBox var4) throws IOException {
      if (this.hasOutboundDataInternal()) {
         HandshakeStatus var5 = this.getOutboundData(var2.netData);
         if (debug != null && Debug.isOn("packet")) {
            this.dumpPacket(var2, true);
         }

         return var5;
      } else if (this.outboundClosed) {
         throw new IOException("The write side was already closed");
      } else {
         var1.write(var2, var3, var4);
         if (debug != null && Debug.isOn("packet")) {
            this.dumpPacket(var2, false);
         }

         return null;
      }
   }

   void putOutboundData(ByteBuffer var1) {
      this.outboundList.addLast(var1);
   }

   synchronized void putOutboundDataSync(ByteBuffer var1) throws IOException {
      if (this.outboundClosed) {
         throw new IOException("Write side already closed");
      } else {
         this.outboundList.addLast(var1);
      }
   }

   private boolean hasOutboundDataInternal() {
      return this.outboundList.size() != 0;
   }

   synchronized boolean hasOutboundData() {
      return this.hasOutboundDataInternal();
   }

   synchronized boolean isOutboundDone() {
      return this.outboundClosed && !this.hasOutboundDataInternal();
   }

   synchronized void closeOutbound() {
      this.outboundClosed = true;
   }
}
