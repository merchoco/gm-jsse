package cn.gmssl.sun.security.ssl;

import cn.gmssl.security.util.Cache;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

final class SSLSessionContextImpl implements SSLSessionContext {
   private Cache sessionCache;
   private Cache sessionHostPortCache;
   private int cacheLimit = this.getDefaultCacheLimit();
   private int timeout = 86400;
   private static final Debug debug = Debug.getInstance("ssl");

   SSLSessionContextImpl() {
      this.sessionCache = Cache.newSoftMemoryCache(this.cacheLimit, this.timeout);
      this.sessionHostPortCache = Cache.newSoftMemoryCache(this.cacheLimit, this.timeout);
   }

   public SSLSession getSession(byte[] var1) {
      if (var1 == null) {
         throw new NullPointerException("session id cannot be null");
      } else {
         SSLSessionImpl var2 = (SSLSessionImpl)this.sessionCache.get(new SessionId(var1));
         return !this.isTimedout(var2) ? var2 : null;
      }
   }

   public Enumeration<byte[]> getIds() {
      SSLSessionContextImpl.SessionCacheVisitor var1 = new SSLSessionContextImpl.SessionCacheVisitor();
      this.sessionCache.accept(var1);
      return var1.getSessionIds();
   }

   public void setSessionTimeout(int var1) throws IllegalArgumentException {
      if (var1 < 0) {
         throw new IllegalArgumentException();
      } else {
         if (this.timeout != var1) {
            this.sessionCache.setTimeout(var1);
            this.sessionHostPortCache.setTimeout(var1);
            this.timeout = var1;
         }

      }
   }

   public int getSessionTimeout() {
      return this.timeout;
   }

   public void setSessionCacheSize(int var1) throws IllegalArgumentException {
      if (var1 < 0) {
         throw new IllegalArgumentException();
      } else {
         if (this.cacheLimit != var1) {
            this.sessionCache.setCapacity(var1);
            this.sessionHostPortCache.setCapacity(var1);
            this.cacheLimit = var1;
         }

      }
   }

   public int getSessionCacheSize() {
      return this.cacheLimit;
   }

   SSLSessionImpl get(byte[] var1) {
      return (SSLSessionImpl)this.getSession(var1);
   }

   SSLSessionImpl get(String var1, int var2) {
      if (var1 == null && var2 == -1) {
         return null;
      } else {
         SSLSessionImpl var3 = (SSLSessionImpl)this.sessionHostPortCache.get(this.getKey(var1, var2));
         return !this.isTimedout(var3) ? var3 : null;
      }
   }

   private String getKey(String var1, int var2) {
      return (var1 + ":" + var2).toLowerCase();
   }

   void put(SSLSessionImpl var1) {
      this.sessionCache.put(var1.getSessionId(), var1);
      if (var1.getPeerHost() != null && var1.getPeerPort() != -1) {
         this.sessionHostPortCache.put(this.getKey(var1.getPeerHost(), var1.getPeerPort()), var1);
      }

      var1.setContext(this);
   }

   void remove(SessionId var1) {
      SSLSessionImpl var2 = (SSLSessionImpl)this.sessionCache.get(var1);
      if (var2 != null) {
         this.sessionCache.remove(var1);
         this.sessionHostPortCache.remove(this.getKey(var2.getPeerHost(), var2.getPeerPort()));
      }

   }

   private int getDefaultCacheLimit() {
      int var1 = 0;

      try {
         String var2 = (String)AccessController.doPrivileged(new PrivilegedAction<String>() {
            public String run() {
               return System.getProperty("javax.net.ssl.sessionCacheSize");
            }
         });
         var1 = var2 != null ? Integer.valueOf(var2) : 0;
      } catch (Exception var3) {
         ;
      }

      return var1 > 0 ? var1 : 0;
   }

   boolean isTimedout(SSLSession var1) {
      if (this.timeout == 0) {
         return false;
      } else if (var1 != null && var1.getCreationTime() + (long)this.timeout * 1000L <= System.currentTimeMillis()) {
         var1.invalidate();
         return true;
      } else {
         return false;
      }
   }

   final class SessionCacheVisitor implements Cache.CacheVisitor {
      Vector<byte[]> ids = null;

      public void visit(Map<Object, Object> var1) {
         this.ids = new Vector(var1.size());
         Iterator var3 = var1.keySet().iterator();

         while(var3.hasNext()) {
            Object var2 = var3.next();
            SSLSessionImpl var4 = (SSLSessionImpl)var1.get(var2);
            if (!SSLSessionContextImpl.this.isTimedout(var4)) {
               this.ids.addElement(((SessionId)var2).getId());
            }
         }

      }

      public Enumeration<byte[]> getSessionIds() {
         return this.ids != null ? this.ids.elements() : (new Vector()).elements();
      }
   }
}
