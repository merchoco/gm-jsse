package cn.gmssl.security.util;

import java.util.Arrays;
import java.util.Map;

public abstract class Cache {
   public abstract int size();

   public abstract void clear();

   public abstract void put(Object var1, Object var2);

   public abstract Object get(Object var1);

   public abstract void remove(Object var1);

   public abstract void setCapacity(int var1);

   public abstract void setTimeout(int var1);

   public abstract void accept(Cache.CacheVisitor var1);

   public static Cache newSoftMemoryCache(int var0) {
      return new MemoryCache(true, var0);
   }

   public static Cache newSoftMemoryCache(int var0, int var1) {
      return new MemoryCache(true, var0, var1);
   }

   public static Cache newHardMemoryCache(int var0) {
      return new MemoryCache(false, var0);
   }

   public static Cache newNullCache() {
      return NullCache.INSTANCE;
   }

   public static Cache newHardMemoryCache(int var0, int var1) {
      return new MemoryCache(false, var0, var1);
   }

   public interface CacheVisitor {
      void visit(Map<Object, Object> var1);
   }

   public static class EqualByteArray {
      private final byte[] b;
      private volatile int hash;

      public EqualByteArray(byte[] var1) {
         this.b = var1;
      }

      public int hashCode() {
         int var1 = this.hash;
         if (var1 == 0) {
            var1 = this.b.length + 1;

            for(int var2 = 0; var2 < this.b.length; ++var2) {
               var1 += (this.b[var2] & 255) * 37;
            }

            this.hash = var1;
         }

         return var1;
      }

      public boolean equals(Object var1) {
         if (this == var1) {
            return true;
         } else if (!(var1 instanceof Cache.EqualByteArray)) {
            return false;
         } else {
            Cache.EqualByteArray var2 = (Cache.EqualByteArray)var1;
            return Arrays.equals(this.b, var2.b);
         }
      }
   }
}
