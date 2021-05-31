package cn.gmssl.security.util;

class NullCache extends Cache {
   static final Cache INSTANCE = new NullCache();

   public int size() {
      return 0;
   }

   public void clear() {
   }

   public void put(Object var1, Object var2) {
   }

   public Object get(Object var1) {
      return null;
   }

   public void remove(Object var1) {
   }

   public void setCapacity(int var1) {
   }

   public void setTimeout(int var1) {
   }

   public void accept(Cache.CacheVisitor var1) {
   }
}
