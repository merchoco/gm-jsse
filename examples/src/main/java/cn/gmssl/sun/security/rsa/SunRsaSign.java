package cn.gmssl.sun.security.rsa;

import java.security.AccessController;
import java.security.Provider;
import java.util.HashMap;
import sun.security.action.PutAllAction;
import sun.security.rsa.SunRsaSignEntries;

public final class SunRsaSign extends Provider {
   private static final long serialVersionUID = 866040293550393045L;

   public SunRsaSign() {
      super("SunRsaSign", 1.7D, "Sun RSA signature provider");
      if (System.getSecurityManager() == null) {
         //SunRsaSignEntries.putEntaries(this);
      } else {
         HashMap var1 = new HashMap();
        // SunRsaSignEntries.putEntries(var1);
         AccessController.doPrivileged(new PutAllAction(this, var1));
      }

   }
}
