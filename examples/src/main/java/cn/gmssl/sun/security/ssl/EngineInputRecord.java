package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import javax.crypto.BadPaddingException;
import javax.net.ssl.SSLException;
import sun.misc.HexDumpEncoder;

final class EngineInputRecord extends InputRecord {
   private SSLEngineImpl engine;
   private static ByteBuffer tmpBB = ByteBuffer.allocate(0);
   private boolean internalData;

   EngineInputRecord(SSLEngineImpl var1) {
      this.engine = var1;
   }

   byte contentType() {
      return this.internalData ? super.contentType() : 23;
   }

   int bytesInCompletePacket(ByteBuffer var1) throws SSLException {
      if (var1.remaining() < 5) {
         return -1;
      } else {
         int var2 = var1.position();
         byte var3 = var1.get(var2);
         boolean var4 = false;
         int var8;
         if (!this.formatVerified && var3 != 22 && var3 != 21) {
            boolean var9 = (var3 & 128) != 0;
            if (!var9 || var1.get(var2 + 2) != 1 && var1.get(var2 + 2) != 4) {
               throw new SSLException("Unrecognized SSL message, plaintext connection?");
            }

            ProtocolVersion var6 = ProtocolVersion.valueOf(var1.get(var2 + 3), var1.get(var2 + 4));
            if ((var6.v < ProtocolVersion.MIN.v || var6.major > ProtocolVersion.MAX.major) && var6.v != ProtocolVersion.SSL20Hello.v) {
               throw new SSLException("Unsupported record version " + var6);
            }

            int var7 = var9 ? 127 : 63;
            var8 = ((var3 & var7) << 8) + (var1.get(var2 + 1) & 255) + (var9 ? 2 : 3);
         } else {
            ProtocolVersion var5 = ProtocolVersion.valueOf(var1.get(var2 + 1), var1.get(var2 + 2));
            if (var5.v < ProtocolVersion.MIN.v || var5.major > ProtocolVersion.MAX.major) {
               throw new SSLException("Unsupported record version " + var5);
            }

            this.formatVerified = true;
            var8 = ((var1.get(var2 + 3) & 255) << 8) + (var1.get(var2 + 4) & 255) + 5;
         }

         return var8;
      }
   }

   boolean checkMAC(MAC var1, ByteBuffer var2) {
      if (this.internalData) {
         return this.checkMAC(var1);
      } else {
         int var3 = var1.MAClen();
         if (var3 == 0) {
            return true;
         } else {
            int var4 = var2.limit();
            int var5 = var4 - var3;
            var2.limit(var5);
            byte[] var6 = var1.compute(this.contentType(), var2);
            if (var3 != var6.length) {
               throw new RuntimeException("Internal MAC error");
            } else {
               var2.position(var5);
               var2.limit(var4);

               try {
                  for(int var7 = 0; var7 < var3; ++var7) {
                     if (var2.get() != var6[var7]) {
                        return false;
                     }
                  }
               } finally {
                  var2.rewind();
                  var2.limit(var5);
               }

               return true;
            }
         }
      }
   }

   ByteBuffer decrypt(CipherBox var1, ByteBuffer var2) throws BadPaddingException {
      if (this.internalData) {
         this.decrypt(var1);
         return tmpBB;
      } else {
         var1.decrypt(var2);
         var2.rewind();
         return var2.slice();
      }
   }

   void writeBuffer(OutputStream var1, byte[] var2, int var3, int var4) throws IOException {
      ByteBuffer var5 = (ByteBuffer)ByteBuffer.allocate(var4).put(var2, 0, var4).flip();
      this.engine.writer.putOutboundDataSync(var5);
   }

   ByteBuffer read(ByteBuffer var1) throws IOException {
      if (this.formatVerified && var1.get(var1.position()) == 23) {
         this.internalData = false;
         int var2 = var1.position();
         int var3 = var1.limit();
         ProtocolVersion var4 = ProtocolVersion.valueOf(var1.get(var2 + 1), var1.get(var2 + 2));
         if (var4.v >= ProtocolVersion.MIN.v && var4.major <= ProtocolVersion.MAX.major) {
            int var5 = this.bytesInCompletePacket(var1);

            assert var5 > 0;

            if (debug != null && Debug.isOn("packet")) {
               try {
                  HexDumpEncoder var6 = new HexDumpEncoder();
                  var1.limit(var2 + var5);
                  ByteBuffer var7 = var1.duplicate();
                  System.out.println("[Raw read (bb)]: length = " + var5);
                  var6.encodeBuffer(var7, System.out);
               } catch (IOException var8) {
                  ;
               }
            }

            var1.position(var2 + 5);
            var1.limit(var2 + var5);
            ByteBuffer var9 = var1.slice();
            var1.position(var1.limit());
            var1.limit(var3);
            return var9;
         } else {
            throw new SSLException("Unsupported record version " + var4);
         }
      } else {
         this.internalData = true;
         this.read(new ByteBufferInputStream(var1), (OutputStream)null);
         return tmpBB;
      }
   }
}
