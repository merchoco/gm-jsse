package org.bc.crypto.tls;

import java.io.IOException;

public class ProtocolVersion {
   public static final ProtocolVersion SSLv3 = new ProtocolVersion(768);
   public static final ProtocolVersion TLSv10 = new ProtocolVersion(769);
   public static final ProtocolVersion TLSv11 = new ProtocolVersion(770);
   public static final ProtocolVersion TLSv12 = new ProtocolVersion(771);
   private int version;

   private ProtocolVersion(int var1) {
      this.version = var1 & '\uffff';
   }

   public int getFullVersion() {
      return this.version;
   }

   public int getMajorVersion() {
      return this.version >> 8;
   }

   public int getMinorVersion() {
      return this.version & 255;
   }

   public boolean equals(Object var1) {
      return this == var1;
   }

   public int hashCode() {
      return this.version;
   }

   public static ProtocolVersion get(int var0, int var1) throws IOException {
      switch(var0) {
      case 3:
         switch(var1) {
         case 0:
            return SSLv3;
         case 1:
            return TLSv10;
         case 2:
            return TLSv11;
         case 3:
            return TLSv12;
         }
      default:
         throw new TlsFatalAlert((short)47);
      }
   }
}
