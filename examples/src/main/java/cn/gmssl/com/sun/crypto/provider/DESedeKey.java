package cn.gmssl.com.sun.crypto.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;
import java.security.InvalidKeyException;
import java.security.KeyRep;
import java.security.KeyRep.Type;
import java.util.Arrays;
import javax.crypto.SecretKey;

final class DESedeKey implements SecretKey {
   static final long serialVersionUID = 2463986565756745178L;
   private byte[] key;

   DESedeKey(byte[] var1) throws InvalidKeyException {
      this(var1, 0);
   }

   DESedeKey(byte[] var1, int var2) throws InvalidKeyException {
      if (var1 != null && var1.length - var2 >= 24) {
         this.key = new byte[24];
         System.arraycopy(var1, var2, this.key, 0, 24);
         DESKeyGenerator.setParityBit(this.key, 0);
         DESKeyGenerator.setParityBit(this.key, 8);
         DESKeyGenerator.setParityBit(this.key, 16);
      } else {
         throw new InvalidKeyException("Wrong key size");
      }
   }

   public byte[] getEncoded() {
      return (byte[])this.key.clone();
   }

   public String getAlgorithm() {
      return "DESede";
   }

   public String getFormat() {
      return "RAW";
   }

   public int hashCode() {
      int var1 = 0;

      for(int var2 = 1; var2 < this.key.length; ++var2) {
         var1 += this.key[var2] * var2;
      }

      return var1 ^ "desede".hashCode();
   }

   public boolean equals(Object var1) {
      if (this == var1) {
         return true;
      } else if (!(var1 instanceof SecretKey)) {
         return false;
      } else {
         String var2 = ((SecretKey)var1).getAlgorithm();
         if (!var2.equalsIgnoreCase("DESede") && !var2.equalsIgnoreCase("TripleDES")) {
            return false;
         } else {
            byte[] var3 = ((SecretKey)var1).getEncoded();
            boolean var4 = Arrays.equals(this.key, var3);
            Arrays.fill(var3, (byte)0);
            return var4;
         }
      }
   }

   private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
      var1.defaultReadObject();
      this.key = (byte[])this.key.clone();
   }

   private Object writeReplace() throws ObjectStreamException {
      return new KeyRep(Type.SECRET, this.getAlgorithm(), this.getFormat(), this.getEncoded());
   }

   protected void finalize() throws Throwable {
      try {
         if (this.key != null) {
            Arrays.fill(this.key, (byte)0);
            this.key = null;
         }
      } finally {
         super.finalize();
      }

   }
}
