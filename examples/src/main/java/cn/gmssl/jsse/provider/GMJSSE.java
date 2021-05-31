package cn.gmssl.jsse.provider;

import cn.gmssl.sun.security.ssl.MyJSSE;
import java.security.Provider;

public final class GMJSSE extends MyJSSE {
   private static final long serialVersionUID = 3231825739635378733L;
   public static final String NAME = "GMJSSE";
   public static final String GMSSLv10 = "GMSSLv1.0";
   public static final String GMSSLv11 = "GMSSLv1.1";

   public GMJSSE() {
   }

   public GMJSSE(Provider var1) {
      super(var1);
   }

   public GMJSSE(String var1) {
      super(var1);
   }

   public static synchronized boolean isFIPS() {
      return isFIPS();
   }

   public static synchronized void install() {
   }
}
