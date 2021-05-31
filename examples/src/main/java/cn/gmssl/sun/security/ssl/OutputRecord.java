package cn.gmssl.sun.security.ssl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLException;
import sun.misc.HexDumpEncoder;

class OutputRecord extends ByteArrayOutputStream implements Record {
   private HandshakeHash handshakeHash;
   private int lastHashed;
   private boolean firstMessage;
   private final byte contentType;
   ProtocolVersion protocolVersion;
   private ProtocolVersion helloVersion;
   static final Debug debug = Debug.getInstance("ssl");
   private static int[] V3toV2CipherMap1 = new int[]{-1, -1, -1, 2, 1, -1, 4, 5, -1, 6, 7};
   private static int[] V3toV2CipherMap3 = new int[]{-1, -1, -1, 128, 128, -1, 128, 128, -1, 64, 192};

   OutputRecord(byte var1, int var2) {
      super(var2);
      this.protocolVersion = ProtocolVersion.DEFAULT;
      this.helloVersion = ProtocolVersion.DEFAULT_HELLO;
      this.firstMessage = true;
      this.count = 5;
      this.contentType = var1;
      this.lastHashed = this.count;
   }

   OutputRecord(byte var1) {
      this(var1, recordSize(var1));
   }

   private static int recordSize(byte var0) {
      return var0 != 20 && var0 != 21 ? 16921 : 539;
   }

   synchronized void setVersion(ProtocolVersion var1) {
      this.protocolVersion = var1;
   }

   synchronized void setHelloVersion(ProtocolVersion var1) {
      this.helloVersion = var1;
   }

   public synchronized void reset() {
      super.reset();
      this.count = 5;
      this.lastHashed = this.count;
   }

   void setHandshakeHash(HandshakeHash var1) {
      assert this.contentType == 22;

      this.handshakeHash = var1;
   }

   void doHashes() {
      int var1 = this.count - this.lastHashed;
      if (var1 > 0) {
         this.hashInternal(this.buf, this.lastHashed, var1);
         this.lastHashed = this.count;
      }

   }

   private void hashInternal(byte[] var1, int var2, int var3) {
      if (debug != null && Debug.isOn("data")) {
         try {
            HexDumpEncoder var4 = new HexDumpEncoder();
            System.out.println("[write] MD5 and SHA1 hashes:  len = " + var3);
            var4.encodeBuffer(new ByteArrayInputStream(var1, this.lastHashed, var3), System.out);
         } catch (IOException var5) {
            ;
         }
      }

      this.handshakeHash.update(var1, this.lastHashed, var3);
      this.lastHashed = this.count;
   }

   boolean isEmpty() {
      return this.count == 5;
   }

   boolean isAlert(byte var1) {
      if (this.count > 6 && this.contentType == 21) {
         return this.buf[6] == var1;
      } else {
         return false;
      }
   }

   void addMAC(MAC var1) throws IOException {
      if (this.contentType == 22) {
         this.doHashes();
      }

      if (var1.MAClen() != 0) {
         byte[] var2 = var1.compute(this.contentType, this.buf, 5, this.count - 5);
         this.write(var2);
      }

   }

   void encrypt(CipherBox var1) {
      int var2 = this.count - 5;
      this.count = 5 + var1.encrypt(this.buf, 5, var2);
   }

   final int availableDataBytes() {
      int var1 = this.count - 5;
      return 16384 - var1;
   }

   final byte contentType() {
      return this.contentType;
   }

   void write(OutputStream var1) throws IOException {
      if (this.count != 5) {
         int var2 = this.count - 5;
         if (var2 < 0) {
            throw new SSLException("output record size too small: " + var2);
         } else {
            if (debug != null && (Debug.isOn("record") || Debug.isOn("handshake")) && (debug != null && Debug.isOn("record") || this.contentType() == 20)) {
               System.out.println(Thread.currentThread().getName() + ", WRITE: " + this.protocolVersion + " " + InputRecord.contentName(this.contentType()) + ", length = " + var2);
            }

            if (this.firstMessage && this.useV2Hello()) {
               byte[] var3 = new byte[var2 - 4];
               System.arraycopy(this.buf, 9, var3, 0, var3.length);
               this.V3toV2ClientHello(var3);
               this.handshakeHash.reset();
               this.lastHashed = 2;
               this.doHashes();
               if (debug != null && Debug.isOn("record")) {
                  System.out.println(Thread.currentThread().getName() + ", WRITE: SSLv2 client hello message" + ", length = " + (this.count - 2));
               }
            } else {
               this.buf[0] = this.contentType;
               this.buf[1] = this.protocolVersion.major;
               this.buf[2] = this.protocolVersion.minor;
               this.buf[3] = (byte)(var2 >> 8);
               this.buf[4] = (byte)var2;
            }

            this.firstMessage = false;
            this.writeBuffer(var1, this.buf, 0, this.count);
            this.reset();
         }
      }
   }

   void writeBuffer(OutputStream var1, byte[] var2, int var3, int var4) throws IOException {
      var1.write(var2, var3, var4);
      var1.flush();
      if (debug != null && Debug.isOn("packet")) {
         try {
            HexDumpEncoder var5 = new HexDumpEncoder();
            ByteBuffer var6 = ByteBuffer.wrap(var2, var3, var4);
            System.out.println("[Raw write]: length = " + var6.remaining());
            var5.encodeBuffer(var6, System.out);
         } catch (IOException var7) {
            ;
         }
      }

   }

   private boolean useV2Hello() {
      return this.firstMessage && this.helloVersion == ProtocolVersion.SSL20Hello && this.contentType == 22 && this.buf[5] == 1 && this.buf[43] == 0;
   }

   private void V3toV2ClientHello(byte[] var1) throws SSLException {
      byte var2 = 34;
      byte var3 = var1[var2];
      int var4 = var2 + 1 + var3;
      int var5 = ((var1[var4] & 255) << 8) + (var1[var4 + 1] & 255);
      int var6 = var5 / 2;
      int var7 = var4 + 2;
      int var8 = 0;
      this.count = 11;
      boolean var9 = false;

      for(int var10 = 0; var10 < var6; ++var10) {
         byte var11 = var1[var7++];
         byte var12 = var1[var7++];
         var8 += this.V3toV2CipherSuite(var11, var12);
         if (!var9 && var11 == 0 && var12 == -1) {
            var9 = true;
         }
      }

      if (!var9) {
         var8 += this.V3toV2CipherSuite((byte)0, (byte)-1);
      }

      this.buf[2] = 1;
      this.buf[3] = var1[0];
      this.buf[4] = var1[1];
      this.buf[5] = (byte)(var8 >>> 8);
      this.buf[6] = (byte)var8;
      this.buf[7] = 0;
      this.buf[8] = 0;
      this.buf[9] = 0;
      this.buf[10] = 32;
      System.arraycopy(var1, 2, this.buf, this.count, 32);
      this.count += 32;
      this.count -= 2;
      this.buf[0] = (byte)(this.count >>> 8);
      this.buf[0] = (byte)(this.buf[0] | 128);
      this.buf[1] = (byte)this.count;
      this.count += 2;
   }

   private int V3toV2CipherSuite(byte var1, byte var2) {
      this.buf[this.count++] = 0;
      this.buf[this.count++] = var1;
      this.buf[this.count++] = var2;
      if ((var2 & 255) <= 10 && V3toV2CipherMap1[var2] != -1) {
         this.buf[this.count++] = (byte)V3toV2CipherMap1[var2];
         this.buf[this.count++] = 0;
         this.buf[this.count++] = (byte)V3toV2CipherMap3[var2];
         return 6;
      } else {
         return 3;
      }
   }
}
