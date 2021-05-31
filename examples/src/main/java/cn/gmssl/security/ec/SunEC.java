package cn.gmssl.security.ec;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.HashMap;
import sun.security.action.PutAllAction;

public final class SunEC extends Provider {
   private static final long serialVersionUID = -2279741672933606418L;
   private static boolean useFullImplementation = true;

   static {
      try {
         AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
               System.loadLibrary("sunec");
               return null;
            }
         });
      } catch (UnsatisfiedLinkError var1) {
         useFullImplementation = false;
      }

   }

   public SunEC() {
      super("SunEC", 1.7D, "Sun Elliptic Curve provider (EC, ECDSA, ECDH)");
      if (System.getSecurityManager() == null) {
         SunECEntries.putEntries(this, useFullImplementation);
      } else {
         HashMap var1 = new HashMap();
         SunECEntries.putEntries(var1, useFullImplementation);
         AccessController.doPrivileged(new PutAllAction(this, var1));
      }

   }
}
