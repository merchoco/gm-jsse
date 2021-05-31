package cn.gmssl.sun.security.ssl;

public final class ProtocolVersion implements Comparable<ProtocolVersion> {
   static final int LIMIT_MAX_VALUE = 65535;
   static final int LIMIT_MIN_VALUE = 769;
   static final ProtocolVersion NONE = new ProtocolVersion(-1, "NONE");
   static final ProtocolVersion SSL20Hello = new ProtocolVersion(2, "SSLv2Hello");
   static final ProtocolVersion SSL30 = new ProtocolVersion(768, "SSLv3");
   static final ProtocolVersion TLS10 = new ProtocolVersion(769, "TLSv1");
   static final ProtocolVersion TLS11 = new ProtocolVersion(770, "TLSv1.1");
   static final ProtocolVersion TLS12 = new ProtocolVersion(771, "TLSv1.2");
   static final ProtocolVersion GMSSL10 = new ProtocolVersion(1, 0, "GMSSLv1.0");
   static final ProtocolVersion GMSSL11 = new ProtocolVersion(1, 1, "GMSSLv1.1");
   private static final boolean FIPS = MyJSSE.isFIPS();
   static final ProtocolVersion MIN;
   static final ProtocolVersion MAX;
   static final ProtocolVersion DEFAULT;
   static final ProtocolVersion DEFAULT_HELLO;
   public final int v;
   public final byte major;
   public final byte minor;
   final String name;

   static {
      MIN = FIPS ? TLS10 : SSL30;
      MAX = TLS12;
      DEFAULT = TLS10;
      DEFAULT_HELLO = FIPS ? TLS10 : SSL30;
   }

   private ProtocolVersion(int var1, String var2) {
      this.v = var1;
      this.name = var2;
      this.major = (byte)(var1 >>> 8);
      this.minor = (byte)(var1 & 255);
   }

   private ProtocolVersion(int var1, int var2, String var3) {
      if (var1 != 1) {
         throw new IllegalArgumentException("major version must be 1");
      } else if (var2 != 0 && var2 != 1) {
         throw new IllegalArgumentException("minor version must be 0 or 1");
      } else {
         this.v = TLS11.v;
         this.major = (byte)var1;
         this.minor = (byte)var2;
         this.name = var3;
      }
   }

   private static ProtocolVersion valueOf(int var0) {
      if (var0 == SSL30.v) {
         return SSL30;
      } else if (var0 == TLS10.v) {
         return TLS10;
      } else if (var0 == TLS11.v) {
         return TLS11;
      } else if (var0 == TLS12.v) {
         return TLS12;
      } else if (var0 == SSL20Hello.v) {
         return SSL20Hello;
      } else {
         int var1 = var0 >>> 8 & 255;
         int var2 = var0 & 255;
         return new ProtocolVersion(var0, "Unknown-" + var1 + "." + var2);
      }
   }

   public static ProtocolVersion valueOf(int var0, int var1) {
      if (var0 == 1) {
         if (var1 == 0) {
            return GMSSL10;
         }

         if (var1 == 1) {
            return GMSSL11;
         }
      }

      var0 &= 255;
      var1 &= 255;
      int var2 = var0 << 8 | var1;
      return valueOf(var2);
   }

   static ProtocolVersion valueOf(String var0) {
      if (var0 == null) {
         throw new IllegalArgumentException("Protocol cannot be null");
      } else if (FIPS && (var0.equals(SSL30.name) || var0.equals(SSL20Hello.name))) {
         throw new IllegalArgumentException("Only TLS 1.0 or later allowed in FIPS mode");
      } else if (var0.equals(SSL30.name)) {
         return SSL30;
      } else if (var0.equals(TLS10.name)) {
         return TLS10;
      } else if (var0.equals(TLS11.name)) {
         return TLS11;
      } else if (var0.equals(TLS12.name)) {
         return TLS12;
      } else if (var0.equals(SSL20Hello.name)) {
         return SSL20Hello;
      } else if (var0.equals(GMSSL10.name)) {
         return GMSSL10;
      } else if (var0.equals(GMSSL11.name)) {
         return GMSSL11;
      } else {
         throw new IllegalArgumentException(var0);
      }
   }

   public String toString() {
      return this.name;
   }

   public int compareTo(ProtocolVersion var1) {
      return this.v - var1.v;
   }
}
