package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.security.spec.ECParameterSpec;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.SSLProtocolException;

final class SupportedEllipticCurvesExtension extends HelloExtension {
   static final SupportedEllipticCurvesExtension DEFAULT;
   private static final boolean fips = MyJSSE.isFIPS();
   private final int[] curveIds;
   private static final int ARBITRARY_PRIME = 65281;
   private static final int ARBITRARY_CHAR2 = 65282;
   private static final String[] NAMED_CURVE_OID_TABLE;
   private static final Map<String, Integer> curveIndices;

   static {
      int[] var0;
      if (!fips) {
         var0 = new int[]{23, 1, 3, 19, 21, 6, 7, 9, 10, 24, 11, 12, 25, 13, 14, 15, 16, 17, 2, 18, 4, 5, 20, 8, 22};
      } else {
         var0 = new int[]{23, 1, 3, 19, 21, 6, 7, 9, 10, 24, 11, 12, 25, 13, 14};
      }

      DEFAULT = new SupportedEllipticCurvesExtension(var0);
      NAMED_CURVE_OID_TABLE = new String[]{null, "1.3.132.0.1", "1.3.132.0.2", "1.3.132.0.15", "1.3.132.0.24", "1.3.132.0.25", "1.3.132.0.26", "1.3.132.0.27", "1.3.132.0.3", "1.3.132.0.16", "1.3.132.0.17", "1.3.132.0.36", "1.3.132.0.37", "1.3.132.0.38", "1.3.132.0.39", "1.3.132.0.9", "1.3.132.0.8", "1.3.132.0.30", "1.3.132.0.31", "1.2.840.10045.3.1.1", "1.3.132.0.32", "1.3.132.0.33", "1.3.132.0.10", "1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35"};
      curveIndices = new HashMap();

      for(int var1 = 1; var1 < NAMED_CURVE_OID_TABLE.length; ++var1) {
         curveIndices.put(NAMED_CURVE_OID_TABLE[var1], var1);
      }

   }

   private SupportedEllipticCurvesExtension(int[] var1) {
      super(ExtensionType.EXT_ELLIPTIC_CURVES);
      this.curveIds = var1;
   }

   SupportedEllipticCurvesExtension(HandshakeInStream var1, int var2) throws IOException {
      super(ExtensionType.EXT_ELLIPTIC_CURVES);
      int var3 = var1.getInt16();
      if ((var2 & 1) == 0 && var3 + 2 == var2) {
         this.curveIds = new int[var3 >> 1];

         for(int var4 = 0; var4 < this.curveIds.length; ++var4) {
            this.curveIds[var4] = var1.getInt16();
         }

      } else {
         throw new SSLProtocolException("Invalid " + this.type + " extension");
      }
   }

   boolean contains(int var1) {
      int[] var5 = this.curveIds;
      int var4 = this.curveIds.length;

      for(int var3 = 0; var3 < var4; ++var3) {
         int var2 = var5[var3];
         if (var1 == var2) {
            return true;
         }
      }

      return false;
   }

   int[] curveIds() {
      return this.curveIds;
   }

   int length() {
      return 6 + (this.curveIds.length << 1);
   }

   void send(HandshakeOutStream var1) throws IOException {
      var1.putInt16(this.type.id);
      int var2 = this.curveIds.length << 1;
      var1.putInt16(var2 + 2);
      var1.putInt16(var2);
      int[] var6 = this.curveIds;
      int var5 = this.curveIds.length;

      for(int var4 = 0; var4 < var5; ++var4) {
         int var3 = var6[var4];
         var1.putInt16(var3);
      }

   }

   public String toString() {
      StringBuilder var1 = new StringBuilder();
      var1.append("Extension " + this.type + ", curve names: {");
      boolean var2 = true;
      int[] var6 = this.curveIds;
      int var5 = this.curveIds.length;

      for(int var4 = 0; var4 < var5; ++var4) {
         int var3 = var6[var4];
         if (var2) {
            var2 = false;
         } else {
            var1.append(", ");
         }

         String var7 = getCurveOid(var3);
         if (var7 != null) {
            ECParameterSpec var8 = JsseJce.getECParameterSpec(var7);
            if (var8 != null) {
               var1.append(var8.toString().split(" ")[0]);
            } else {
               var1.append(var7);
            }
         } else if (var3 == 65281) {
            var1.append("arbitrary_explicit_prime_curves");
         } else if (var3 == 65282) {
            var1.append("arbitrary_explicit_char2_curves");
         } else {
            var1.append("unknown curve " + var3);
         }
      }

      var1.append("}");
      return var1.toString();
   }

   static boolean isSupported(int var0) {
      if (var0 > 0 && var0 < NAMED_CURVE_OID_TABLE.length) {
         return !fips ? true : DEFAULT.contains(var0);
      } else {
         return false;
      }
   }

   static int getCurveIndex(ECParameterSpec var0) {
      String var1 = JsseJce.getNamedCurveOid(var0);
      if (var1 == null) {
         return -1;
      } else {
         Integer var2 = (Integer)curveIndices.get(var1);
         return var2 == null ? -1 : var2;
      }
   }

   static String getCurveOid(int var0) {
      return var0 > 0 && var0 < NAMED_CURVE_OID_TABLE.length ? NAMED_CURVE_OID_TABLE[var0] : null;
   }
}
