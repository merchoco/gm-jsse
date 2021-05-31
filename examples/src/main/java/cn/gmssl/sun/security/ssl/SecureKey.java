package cn.gmssl.sun.security.ssl;

class SecureKey {
   private static Object nullObject = new Object();
   private Object appKey;
   private Object securityCtx;

   static Object getCurrentSecurityContext() {
      SecurityManager var0 = System.getSecurityManager();
      Object var1 = null;
      if (var0 != null) {
         var1 = var0.getSecurityContext();
      }

      if (var1 == null) {
         var1 = nullObject;
      }

      return var1;
   }

   SecureKey(Object var1) {
      this.appKey = var1;
      this.securityCtx = getCurrentSecurityContext();
   }

   Object getAppKey() {
      return this.appKey;
   }

   Object getSecurityContext() {
      return this.securityCtx;
   }

   public int hashCode() {
      return this.appKey.hashCode() ^ this.securityCtx.hashCode();
   }

   public boolean equals(Object var1) {
      return var1 instanceof SecureKey && ((SecureKey)var1).appKey.equals(this.appKey) && ((SecureKey)var1).securityCtx.equals(this.securityCtx);
   }
}
