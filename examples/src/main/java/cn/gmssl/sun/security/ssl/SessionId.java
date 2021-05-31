package cn.gmssl.sun.security.ssl;

import java.security.SecureRandom;

final class SessionId {
   private byte[] sessionId;

   SessionId(boolean var1, SecureRandom var2) {
      if (var1) {
         this.sessionId = (new RandomCookie(var2)).random_bytes;
      } else {
         this.sessionId = new byte[0];
      }

   }

   SessionId(byte[] var1) {
      this.sessionId = var1;
   }

   int length() {
      return this.sessionId.length;
   }

   byte[] getId() {
      return (byte[])this.sessionId.clone();
   }

   public String toString() {
      int var1 = this.sessionId.length;
      StringBuffer var2 = new StringBuffer(10 + 2 * var1);
      var2.append("{");

      for(int var3 = 0; var3 < var1; ++var3) {
         var2.append(255 & this.sessionId[var3]);
         if (var3 != var1 - 1) {
            var2.append(", ");
         }
      }

      var2.append("}");
      return var2.toString();
   }

   public int hashCode() {
      int var1 = 0;

      for(int var2 = 0; var2 < this.sessionId.length; ++var2) {
         var1 += this.sessionId[var2];
      }

      return var1;
   }

   public boolean equals(Object var1) {
      if (!(var1 instanceof SessionId)) {
         return false;
      } else {
         SessionId var2 = (SessionId)var1;
         byte[] var3 = var2.getId();
         if (var3.length != this.sessionId.length) {
            return false;
         } else {
            for(int var4 = 0; var4 < this.sessionId.length; ++var4) {
               if (var3[var4] != this.sessionId[var4]) {
                  return false;
               }
            }

            return true;
         }
      }
   }
}
