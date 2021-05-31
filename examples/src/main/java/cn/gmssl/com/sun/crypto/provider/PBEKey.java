package cn.gmssl.com.sun.crypto.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;
import java.security.KeyRep;
import java.security.KeyRep.Type;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

final class PBEKey implements SecretKey {
   static final long serialVersionUID = -2234768909660948176L;
   private byte[] key;
   private String type;

   PBEKey(PBEKeySpec var1, String var2) throws InvalidKeySpecException {
      char[] var3 = var1.getPassword();
      if (var3 == null) {
         var3 = new char[0];
      }

      int var4;
      for(var4 = 0; var4 < var3.length; ++var4) {
         if (var3[var4] < ' ' || var3[var4] > '~') {
            throw new InvalidKeySpecException("Password is not ASCII");
         }
      }

      this.key = new byte[var3.length];

      for(var4 = 0; var4 < var3.length; ++var4) {
         this.key[var4] = (byte)(var3[var4] & 127);
      }

      Arrays.fill(var3, ' ');
      this.type = var2;
   }

   public byte[] getEncoded() {
      return (byte[])this.key.clone();
   }

   public String getAlgorithm() {
      return this.type;
   }

   public String getFormat() {
      return "RAW";
   }

   public int hashCode() {
      int var1 = 0;

      for(int var2 = 1; var2 < this.key.length; ++var2) {
         var1 += this.key[var2] * var2;
      }

      return var1 ^ this.getAlgorithm().toLowerCase().hashCode();
   }

   public boolean equals(Object var1) {
      if (var1 == this) {
         return true;
      } else if (!(var1 instanceof SecretKey)) {
         return false;
      } else {
         SecretKey var2 = (SecretKey)var1;
         if (!var2.getAlgorithm().equalsIgnoreCase(this.type)) {
            return false;
         } else {
            byte[] var3 = var2.getEncoded();
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
