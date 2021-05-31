package cn.gmssl.sun.security.ssl;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import javax.crypto.BadPaddingException;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import sun.misc.HexDumpEncoder;

class InputRecord extends ByteArrayInputStream implements Record {
   private HandshakeHash handshakeHash;
   private int lastHashed;
   boolean formatVerified = true;
   private boolean isClosed;
   private boolean appDataValid;
   private ProtocolVersion helloVersion;
   static final Debug debug = Debug.getInstance("ssl");
   private int exlen;
   private byte[] v2Buf;
   private static final byte[] v2NoCipher = new byte[]{-128, 3, 0, 0, 1};

   InputRecord() {
      super(new byte[16921]);
      this.setHelloVersion(ProtocolVersion.DEFAULT_HELLO);
      this.pos = 5;
      this.count = 5;
      this.lastHashed = this.count;
      this.exlen = 0;
      this.v2Buf = null;
   }

   void setHelloVersion(ProtocolVersion var1) {
      this.helloVersion = var1;
   }

   ProtocolVersion getHelloVersion() {
      return this.helloVersion;
   }

   void enableFormatChecks() {
      this.formatVerified = false;
   }

   boolean isAppDataValid() {
      return this.appDataValid;
   }

   void setAppDataValid(boolean var1) {
      this.appDataValid = var1;
   }

   byte contentType() {
      return this.buf[0];
   }

   void setHandshakeHash(HandshakeHash var1) {
      this.handshakeHash = var1;
   }

   HandshakeHash getHandshakeHash() {
      return this.handshakeHash;
   }

   boolean checkMAC(MAC var1) {
      int var2 = var1.MAClen();
      if (var2 == 0) {
         return true;
      } else {
         int var3 = this.count - var2;
         if (var3 < 5) {
            return false;
         } else {
            byte[] var4 = var1.compute(this.contentType(), this.buf, 5, var3 - 5);
            if (var2 != var4.length) {
               throw new RuntimeException("Internal MAC error");
            } else {
               for(int var5 = 0; var5 < var2; ++var5) {
                  if (this.buf[var3 + var5] != var4[var5]) {
                     return false;
                  }
               }

               this.count -= var2;
               return true;
            }
         }
      }
   }

   void decrypt(CipherBox var1) throws BadPaddingException {
      int var2 = this.count - 5;
      this.count = 5 + var1.decrypt(this.buf, 5, var2);
   }

   void ignore(int var1) {
      if (var1 > 0) {
         this.pos += var1;
         this.lastHashed = this.pos;
      }

   }

   void doHashes() {
      int var1 = this.pos - this.lastHashed;
      if (var1 > 0) {
         this.hashInternal(this.buf, this.lastHashed, var1);
         this.lastHashed = this.pos;
      }

   }

   private void hashInternal(byte[] var1, int var2, int var3) {
      if (debug != null && Debug.isOn("data")) {
         try {
            HexDumpEncoder var4 = new HexDumpEncoder();
            System.out.println("[read] MD5 and SHA1 hashes:  len = " + var3);
            var4.encodeBuffer(new ByteArrayInputStream(var1, var2, var3), System.out);
         } catch (IOException var5) {
            ;
         }
      }

      this.handshakeHash.update(var1, var2, var3);
   }

   void queueHandshake(InputRecord var1) throws IOException {
      this.doHashes();
      int var2;
      if (this.pos > 5) {
         var2 = this.count - this.pos;
         if (var2 != 0) {
            System.arraycopy(this.buf, this.pos, this.buf, 5, var2);
         }

         this.pos = 5;
         this.lastHashed = this.pos;
         this.count = 5 + var2;
      }

      var2 = var1.available() + this.count;
      if (this.buf.length < var2) {
         byte[] var3 = new byte[var2];
         System.arraycopy(this.buf, 0, var3, 0, this.count);
         this.buf = var3;
      }

      System.arraycopy(var1.buf, var1.pos, this.buf, this.count, var2 - this.count);
      this.count = var2;
      var2 = var1.lastHashed - var1.pos;
      if (this.pos == 5) {
         this.lastHashed += var2;
         var1.pos = var1.count;
      } else {
         throw new SSLProtocolException("?? confused buffer hashing ??");
      }
   }

   public void close() {
      this.appDataValid = false;
      this.isClosed = true;
      this.mark = 0;
      this.pos = 0;
      this.count = 0;
   }

   private int readFully(InputStream var1, byte[] var2, int var3, int var4) throws IOException {
      int var5;
      int var6;
      for(var5 = 0; var5 < var4; this.exlen += var6) {
         var6 = var1.read(var2, var3 + var5, var4 - var5);
         if (var6 < 0) {
            return var6;
         }

         if (debug != null && Debug.isOn("packet")) {
            try {
               HexDumpEncoder var7 = new HexDumpEncoder();
               ByteBuffer var8 = ByteBuffer.wrap(var2, var3 + var5, var6);
               System.out.println("[Raw read]: length = " + var8.remaining());
               var7.encodeBuffer(var8, System.out);
            } catch (IOException var9) {
               ;
            }
         }

         var5 += var6;
      }

      return var5;
   }

   void read(InputStream var1, OutputStream var2) throws IOException {
      if (!this.isClosed) {
         if (this.exlen < 5) {
            int var3 = this.readFully(var1, this.buf, this.exlen, 5 - this.exlen);
            if (var3 < 0) {
               throw new EOFException("SSL peer shut down incorrectly");
            }

            this.pos = 5;
            this.count = 5;
            this.lastHashed = this.pos;
         }

         if (!this.formatVerified) {
            this.formatVerified = true;
            if (this.buf[0] != 22 && this.buf[0] != 21) {
               this.handleUnknownRecord(var1, var2);
            } else {
               this.readV3Record(var1, var2);
            }
         } else {
            this.readV3Record(var1, var2);
         }

      }
   }

   private void readV3Record(InputStream var1, OutputStream var2) throws IOException {
      ProtocolVersion var3 = ProtocolVersion.valueOf(this.buf[1], this.buf[2]);
      if (var3.v >= ProtocolVersion.MIN.v && var3.major <= ProtocolVersion.MAX.major) {
         int var4 = ((this.buf[3] & 255) << 8) + (this.buf[4] & 255);
         if (var4 >= 0 && var4 <= 33300) {
            if (var4 > this.buf.length - 5) {
               byte[] var5 = new byte[var4 + 5];
               System.arraycopy(this.buf, 0, var5, 0, 5);
               this.buf = var5;
            }

            if (this.exlen < var4 + 5) {
               int var6 = this.readFully(var1, this.buf, this.exlen, var4 + 5 - this.exlen);
               if (var6 < 0) {
                  throw new SSLException("SSL peer shut down incorrectly");
               }
            }

            this.count = var4 + 5;
            this.exlen = 0;
            if (debug != null && Debug.isOn("record")) {
               if (this.count < 0 || this.count > 16916) {
                  System.out.println(Thread.currentThread().getName() + ", Bad InputRecord size" + ", count = " + this.count);
               }

               System.out.println(Thread.currentThread().getName() + ", READ: " + var3 + " " + contentName(this.contentType()) + ", length = " + this.available());
            }

         } else {
            throw new SSLProtocolException("Bad InputRecord size, count = " + var4 + ", buf.length = " + this.buf.length);
         }
      } else {
         throw new SSLException("Unsupported record version " + var3);
      }
   }

   private void handleUnknownRecord(InputStream var1, OutputStream var2) throws IOException {
      if ((this.buf[0] & 128) != 0 && this.buf[2] == 1) {
         if (this.helloVersion != ProtocolVersion.SSL20Hello) {
            throw new SSLHandshakeException("SSLv2Hello is disabled");
         } else {
            ProtocolVersion var7 = ProtocolVersion.valueOf(this.buf[3], this.buf[4]);
            if (var7 == ProtocolVersion.SSL20Hello) {
               try {
                  this.writeBuffer(var2, v2NoCipher, 0, v2NoCipher.length);
               } catch (Exception var6) {
                  ;
               }

               throw new SSLException("Unsupported SSL v2.0 ClientHello");
            } else {
               int var4 = ((this.buf[0] & 127) << 8) + (this.buf[1] & 255) - 3;
               if (this.v2Buf == null) {
                  this.v2Buf = new byte[var4];
               }

               if (this.exlen < var4 + 5) {
                  int var5 = this.readFully(var1, this.v2Buf, this.exlen - 5, var4 + 5 - this.exlen);
                  if (var5 < 0) {
                     throw new EOFException("SSL peer shut down incorrectly");
                  }
               }

               this.exlen = 0;
               this.hashInternal(this.buf, 2, 3);
               this.hashInternal(this.v2Buf, 0, var4);
               this.V2toV3ClientHello(this.v2Buf);
               this.v2Buf = null;
               this.lastHashed = this.count;
               if (debug != null && Debug.isOn("record")) {
                  System.out.println(Thread.currentThread().getName() + ", READ:  SSL v2, contentType = " + contentName(this.contentType()) + ", translated length = " + this.available());
               }

            }
         }
      } else if ((this.buf[0] & 128) != 0 && this.buf[2] == 4) {
         throw new SSLException("SSL V2.0 servers are not supported.");
      } else {
         for(int var3 = 0; var3 < v2NoCipher.length; ++var3) {
            if (this.buf[var3] != v2NoCipher[var3]) {
               throw new SSLException("Unrecognized SSL message, plaintext connection?");
            }
         }

         throw new SSLException("SSL V2.0 servers are not supported.");
      }
   }

   void writeBuffer(OutputStream var1, byte[] var2, int var3, int var4) throws IOException {
      var1.write(var2, 0, var4);
      var1.flush();
   }

   private void V2toV3ClientHello(byte[] var1) throws SSLException {
      this.buf[0] = 22;
      this.buf[1] = this.buf[3];
      this.buf[2] = this.buf[4];
      this.buf[5] = 1;
      this.buf[9] = this.buf[1];
      this.buf[10] = this.buf[2];
      this.count = 11;
      int var3 = ((var1[0] & 255) << 8) + (var1[1] & 255);
      int var4 = ((var1[2] & 255) << 8) + (var1[3] & 255);
      int var5 = ((var1[4] & 255) << 8) + (var1[5] & 255);
      int var6 = 6 + var3 + var4;
      int var2;
      if (var5 < 32) {
         for(var2 = 0; var2 < 32 - var5; ++var2) {
            this.buf[this.count++] = 0;
         }

         System.arraycopy(var1, var6, this.buf, this.count, var5);
         this.count += var5;
      } else {
         System.arraycopy(var1, var6 + (var5 - 32), this.buf, this.count, 32);
         this.count += 32;
      }

      var6 -= var4;
      this.buf[this.count++] = (byte)var4;
      System.arraycopy(var1, var6, this.buf, this.count, var4);
      this.count += var4;
      var6 -= var3;
      int var7 = this.count + 2;

      for(var2 = 0; var2 < var3; var2 += 3) {
         if (var1[var6 + var2] == 0) {
            this.buf[var7++] = var1[var6 + var2 + 1];
            this.buf[var7++] = var1[var6 + var2 + 2];
         }
      }

      var7 -= this.count + 2;
      this.buf[this.count++] = (byte)(var7 >>> 8);
      this.buf[this.count++] = (byte)var7;
      this.count += var7;
      this.buf[this.count++] = 1;
      this.buf[this.count++] = 0;
      this.buf[3] = (byte)(this.count - 5);
      this.buf[4] = (byte)(this.count - 5 >>> 8);
      this.buf[6] = 0;
      this.buf[7] = (byte)(this.count - 5 - 4 >>> 8);
      this.buf[8] = (byte)(this.count - 5 - 4);
      this.pos = 5;
   }

   static String contentName(int var0) {
      switch(var0) {
      case 20:
         return "Change Cipher Spec";
      case 21:
         return "Alert";
      case 22:
         return "Handshake";
      case 23:
         return "Application Data";
      default:
         return "contentType = " + var0;
      }
   }
}
