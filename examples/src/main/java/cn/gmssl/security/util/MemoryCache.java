package cn.gmssl.security.util;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

class MemoryCache extends Cache {
   private static final float LOAD_FACTOR = 0.75F;
   private static final boolean DEBUG = false;
   private final Map<Object, MemoryCache.CacheEntry> cacheMap;
   private int maxSize;
   private long lifetime;
   private final ReferenceQueue queue;

   public MemoryCache(boolean var1, int var2) {
      this(var1, var2, 0);
   }

   public MemoryCache(boolean var1, int var2, int var3) {
      this.maxSize = var2;
      this.lifetime = (long)(var3 * 1000);
      this.queue = var1 ? new ReferenceQueue() : null;
      int var4 = (int)((float)var2 / 0.75F) + 1;
      this.cacheMap = new LinkedHashMap(var4, 0.75F, true);
   }

   private void emptyQueue() {
      if (this.queue != null) {
         int var1 = this.cacheMap.size();

         while(true) {
            MemoryCache.CacheEntry var2 = (MemoryCache.CacheEntry)this.queue.poll();
            if (var2 == null) {
               return;
            }

            Object var3 = var2.getKey();
            if (var3 != null) {
               MemoryCache.CacheEntry var4 = (MemoryCache.CacheEntry)this.cacheMap.remove(var3);
               if (var4 != null && var2 != var4) {
                  this.cacheMap.put(var3, var4);
               }
            }
         }
      }
   }

   private void expungeExpiredEntries() {
      this.emptyQueue();
      if (this.lifetime != 0L) {
         int var1 = 0;
         long var2 = System.currentTimeMillis();
         Iterator var4 = this.cacheMap.values().iterator();

         while(var4.hasNext()) {
            MemoryCache.CacheEntry var5 = (MemoryCache.CacheEntry)var4.next();
            if (!var5.isValid(var2)) {
               var4.remove();
               ++var1;
            }
         }

      }
   }

   public synchronized int size() {
      this.expungeExpiredEntries();
      return this.cacheMap.size();
   }

   public synchronized void clear() {
      if (this.queue != null) {
         Iterator var2 = this.cacheMap.values().iterator();

         while(var2.hasNext()) {
            MemoryCache.CacheEntry var1 = (MemoryCache.CacheEntry)var2.next();
            var1.invalidate();
         }

         while(this.queue.poll() != null) {
            ;
         }
      }

      this.cacheMap.clear();
   }

   public synchronized void put(Object var1, Object var2) {
      this.emptyQueue();
      long var3 = this.lifetime == 0L ? 0L : System.currentTimeMillis() + this.lifetime;
      MemoryCache.CacheEntry var5 = this.newEntry(var1, var2, var3, this.queue);
      MemoryCache.CacheEntry var6 = (MemoryCache.CacheEntry)this.cacheMap.put(var1, var5);
      if (var6 != null) {
         var6.invalidate();
      } else {
         if (this.maxSize > 0 && this.cacheMap.size() > this.maxSize) {
            this.expungeExpiredEntries();
            if (this.cacheMap.size() > this.maxSize) {
               Iterator var7 = this.cacheMap.values().iterator();
               MemoryCache.CacheEntry var8 = (MemoryCache.CacheEntry)var7.next();
               var7.remove();
               var8.invalidate();
            }
         }

      }
   }

   public synchronized Object get(Object var1) {
      this.emptyQueue();
      MemoryCache.CacheEntry var2 = (MemoryCache.CacheEntry)this.cacheMap.get(var1);
      if (var2 == null) {
         return null;
      } else {
         long var3 = this.lifetime == 0L ? 0L : System.currentTimeMillis();
         if (!var2.isValid(var3)) {
            this.cacheMap.remove(var1);
            return null;
         } else {
            return var2.getValue();
         }
      }
   }

   public synchronized void remove(Object var1) {
      this.emptyQueue();
      MemoryCache.CacheEntry var2 = (MemoryCache.CacheEntry)this.cacheMap.remove(var1);
      if (var2 != null) {
         var2.invalidate();
      }

   }

   public synchronized void setCapacity(int var1) {
      this.expungeExpiredEntries();
      if (var1 > 0 && this.cacheMap.size() > var1) {
         Iterator var2 = this.cacheMap.values().iterator();

         for(int var3 = this.cacheMap.size() - var1; var3 > 0; --var3) {
            MemoryCache.CacheEntry var4 = (MemoryCache.CacheEntry)var2.next();
            var2.remove();
            var4.invalidate();
         }
      }

      this.maxSize = var1 > 0 ? var1 : 0;
   }

   public synchronized void setTimeout(int var1) {
      this.emptyQueue();
      this.lifetime = var1 > 0 ? (long)var1 * 1000L : 0L;
   }

   public synchronized void accept(Cache.CacheVisitor var1) {
      this.expungeExpiredEntries();
      Map var2 = this.getCachedEntries();
      var1.visit(var2);
   }

   private Map<Object, Object> getCachedEntries() {
      HashMap var1 = new HashMap(this.cacheMap.size());
      Iterator var3 = this.cacheMap.values().iterator();

      while(var3.hasNext()) {
         MemoryCache.CacheEntry var2 = (MemoryCache.CacheEntry)var3.next();
         var1.put(var2.getKey(), var2.getValue());
      }

      return var1;
   }

   protected MemoryCache.CacheEntry newEntry(Object var1, Object var2, long var3, ReferenceQueue var5) {
      return (MemoryCache.CacheEntry)(var5 != null ? new MemoryCache.SoftCacheEntry(var1, var2, var3, var5) : new MemoryCache.HardCacheEntry(var1, var2, var3));
   }

   private interface CacheEntry {
      boolean isValid(long var1);

      void invalidate();

      Object getKey();

      Object getValue();
   }

   private static class HardCacheEntry implements MemoryCache.CacheEntry {
      private Object key;
      private Object value;
      private long expirationTime;

      HardCacheEntry(Object var1, Object var2, long var3) {
         this.key = var1;
         this.value = var2;
         this.expirationTime = var3;
      }

      public Object getKey() {
         return this.key;
      }

      public Object getValue() {
         return this.value;
      }

      public boolean isValid(long var1) {
         boolean var3 = var1 <= this.expirationTime;
         if (!var3) {
            this.invalidate();
         }

         return var3;
      }

      public void invalidate() {
         this.key = null;
         this.value = null;
         this.expirationTime = -1L;
      }
   }

   private static class SoftCacheEntry extends SoftReference implements MemoryCache.CacheEntry {
      private Object key;
      private long expirationTime;

      SoftCacheEntry(Object var1, Object var2, long var3, ReferenceQueue var5) {
         super(var2, var5);
         this.key = var1;
         this.expirationTime = var3;
      }

      public Object getKey() {
         return this.key;
      }

      public Object getValue() {
         return this.get();
      }

      public boolean isValid(long var1) {
         boolean var3 = var1 <= this.expirationTime && this.get() != null;
         if (!var3) {
            this.invalidate();
         }

         return var3;
      }

      public void invalidate() {
         this.clear();
         this.key = null;
         this.expirationTime = -1L;
      }
   }
}
