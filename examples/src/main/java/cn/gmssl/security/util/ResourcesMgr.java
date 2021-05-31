package cn.gmssl.security.util;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ResourceBundle;

public class ResourcesMgr {
   private static ResourceBundle bundle;
   private static ResourceBundle altBundle;

   public static String getString(String var0) {
      if (bundle == null) {
         bundle = (ResourceBundle)AccessController.doPrivileged(new PrivilegedAction<ResourceBundle>() {
            public ResourceBundle run() {
               return ResourceBundle.getBundle("sun.security.util.Resources");
            }
         });
      }

      return bundle.getString(var0);
   }

   public static String getString(String var0, final String var1) {
      if (altBundle == null) {
         altBundle = (ResourceBundle)AccessController.doPrivileged(new PrivilegedAction<ResourceBundle>() {
            public ResourceBundle run() {
               return ResourceBundle.getBundle(var1);
            }
         });
      }

      return altBundle.getString(var0);
   }
}
