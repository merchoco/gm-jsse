package org.bc.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.bc.crypto.Digest;
import org.bc.crypto.Mac;
import org.bc.crypto.macs.HMac;
import org.bc.crypto.params.KeyParameter;
import org.bc.util.Arrays;

public class TlsMac {
   protected TlsClientContext context;
   protected long seqNo;
   protected byte[] secret;
   protected Mac mac;

   public TlsMac(TlsClientContext var1, Digest var2, byte[] var3, int var4, int var5) {
      this.context = var1;
      this.seqNo = 0L;
      KeyParameter var6 = new KeyParameter(var3, var4, var5);
      this.secret = Arrays.clone(var6.getKey());
      boolean var7 = var1.getServerVersion().getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
      if (var7) {
         this.mac = new HMac(var2);
      } else {
         this.mac = new SSL3Mac(var2);
      }

      this.mac.init(var6);
   }

   public byte[] getMACSecret() {
      return this.secret;
   }

   public long getSequenceNumber() {
      return this.seqNo;
   }

   public void incSequenceNumber() {
      ++this.seqNo;
   }

   public int getSize() {
      return this.mac.getMacSize();
   }

   public byte[] calculateMac(short var1, byte[] var2, int var3, int var4) {
      ProtocolVersion var5 = this.context.getServerVersion();
      boolean var6 = var5.getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
      ByteArrayOutputStream var7 = new ByteArrayOutputStream(var6 ? 13 : 11);

      try {
         TlsUtils.writeUint64((long)(this.seqNo++), var7);
         TlsUtils.writeUint8(var1, var7);
         if (var6) {
            TlsUtils.writeVersion(var5, var7);
         }

         TlsUtils.writeUint16(var4, var7);
      } catch (IOException var10) {
         throw new IllegalStateException("Internal error during mac calculation");
      }

      byte[] var8 = var7.toByteArray();
      this.mac.update(var8, 0, var8.length);
      this.mac.update(var2, var3, var4);
      byte[] var9 = new byte[this.mac.getMacSize()];
      this.mac.doFinal(var9, 0);
      return var9;
   }

   public byte[] calculateMacConstantTime(short var1, byte[] var2, int var3, int var4, int var5, byte[] var6) {
      byte[] var7 = this.calculateMac(var1, var2, var3, var4);
      ProtocolVersion var8 = this.context.getServerVersion();
      boolean var9 = var8.getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
      if (var9) {
         byte var10 = 64;
         byte var11 = 8;
         int var12 = 13 + var5;
         int var13 = 13 + var4;
         int var14 = (var12 + var11) / var10 - (var13 + var11) / var10;

         while(true) {
            --var14;
            if (var14 < 0) {
               this.mac.update(var6[0]);
               this.mac.reset();
               break;
            }

            this.mac.update(var6, 0, var10);
         }
      }

      return var7;
   }
}
