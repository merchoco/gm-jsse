package cn.gmssl.sun.security.ssl;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Permission;
import java.security.Principal;
import java.security.PrivilegedAction;
import javax.crypto.SecretKey;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

public final class Krb5Helper {
   private static final String IMPL_CLASS = "sun.security.ssl.krb5.Krb5ProxyImpl";
   private static final Krb5Proxy proxy = (Krb5Proxy)AccessController.doPrivileged(new PrivilegedAction<Krb5Proxy>() {
      public Krb5Proxy run() {
         try {
            Class var1 = Class.forName("sun.security.ssl.krb5.Krb5ProxyImpl", true, (ClassLoader)null);
            return (Krb5Proxy)var1.newInstance();
         } catch (ClassNotFoundException var2) {
            return null;
         } catch (InstantiationException var3) {
            throw new AssertionError(var3);
         } catch (IllegalAccessException var4) {
            throw new AssertionError(var4);
         }
      }
   });

   public static boolean isAvailable() {
      return proxy != null;
   }

   private static void ensureAvailable() {
      if (proxy == null) {
         throw new AssertionError("Kerberos should have been available");
      }
   }

   public static Subject getClientSubject(AccessControlContext var0) throws LoginException {
      ensureAvailable();
      return proxy.getClientSubject(var0);
   }

   public static Subject getServerSubject(AccessControlContext var0) throws LoginException {
      ensureAvailable();
      return proxy.getServerSubject(var0);
   }

   public static SecretKey[] getServerKeys(AccessControlContext var0) throws LoginException {
      ensureAvailable();
      return proxy.getServerKeys(var0);
   }

   public static String getServerPrincipalName(SecretKey var0) {
      ensureAvailable();
      return proxy.getServerPrincipalName(var0);
   }

   public static String getPrincipalHostName(Principal var0) {
      ensureAvailable();
      return proxy.getPrincipalHostName(var0);
   }

   public static Permission getServicePermission(String var0, String var1) {
      ensureAvailable();
      return proxy.getServicePermission(var0, var1);
   }
}
