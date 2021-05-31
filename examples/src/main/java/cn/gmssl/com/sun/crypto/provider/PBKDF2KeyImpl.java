package cn.gmssl.com.sun.crypto.provider;

import java.io.ObjectStreamException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyRep;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.KeyRep.Type;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

final class PBKDF2KeyImpl implements javax.crypto.interfaces.PBEKey {
   static final long serialVersionUID = -2234868909660948157L;
   private char[] passwd;
   private byte[] salt;
   private int iterCount;
   private byte[] key;
   private Mac prf;

   private static byte[] getPasswordBytes(char[] var0) {
      Charset var1 = Charset.forName("UTF-8");
      CharBuffer var2 = CharBuffer.wrap(var0);
      ByteBuffer var3 = var1.encode(var2);
      int var4 = var3.limit();
      byte[] var5 = new byte[var4];
      var3.get(var5, 0, var4);
      return var5;
   }

   PBKDF2KeyImpl(PBEKeySpec var1, String var2) throws InvalidKeySpecException {
      char[] var3 = var1.getPassword();
      if (var3 == null) {
         this.passwd = new char[0];
      } else {
         this.passwd = (char[])var3.clone();
      }

      byte[] var4 = getPasswordBytes(this.passwd);
      this.salt = var1.getSalt();
      if (this.salt == null) {
         throw new InvalidKeySpecException("Salt not found");
      } else {
         this.iterCount = var1.getIterationCount();
         if (this.iterCount == 0) {
            throw new InvalidKeySpecException("Iteration count not found");
         } else if (this.iterCount < 0) {
            throw new InvalidKeySpecException("Iteration count is negative");
         } else {
            int var5 = var1.getKeyLength();
            if (var5 == 0) {
               throw new InvalidKeySpecException("Key length not found");
            } else if (var5 == 0) {
               throw new InvalidKeySpecException("Key length is negative");
            } else {
               InvalidKeySpecException var7;
               try {
                  this.prf = Mac.getInstance(var2, "SunJCE");
               } catch (NoSuchAlgorithmException var8) {
                  var7 = new InvalidKeySpecException();
                  var7.initCause(var8);
                  throw var7;
               } catch (NoSuchProviderException var9) {
                  var7 = new InvalidKeySpecException();
                  var7.initCause(var9);
                  throw var7;
               }

               this.key = deriveKey(this.prf, var4, this.salt, this.iterCount, var5);
            }
         }
      }
   }

   private static byte[] deriveKey(final Mac var0, final byte[] var1, byte[] var2, int var3, int var4) {
      int var5 = var4 / 8;
      byte[] var6 = new byte[var5];

      try {
         int var7 = var0.getMacLength();
         int var8 = (var5 + var7 - 1) / var7;
         int var9 = var5 - (var8 - 1) * var7;
         byte[] var10 = new byte[var7];
         byte[] var11 = new byte[var7];
         SecretKey var12 = new SecretKey() {
            public String getAlgorithm() {
               return var0.getAlgorithm();
            }

            public String getFormat() {
               return "RAW";
            }

            public byte[] getEncoded() {
               return var1;
            }

            public int hashCode() {
               return Arrays.hashCode(var1) * 41 + var0.getAlgorithm().toLowerCase().hashCode();
            }

            public boolean equals(Object var1x) {
               if (this == var1x) {
                  return true;
               } else if (this.getClass() != var1x.getClass()) {
                  return false;
               } else {
                  SecretKey var2 = (SecretKey)var1x;
                  return var0.getAlgorithm().equalsIgnoreCase(var2.getAlgorithm()) && Arrays.equals(var1, var2.getEncoded());
               }
            }
         };
         var0.init(var12);
         byte[] var13 = new byte[4];

         for(int var14 = 1; var14 <= var8; ++var14) {
            var0.update(var2);
            var13[3] = (byte)var14;
            var13[2] = (byte)(var14 >> 8 & 255);
            var13[1] = (byte)(var14 >> 16 & 255);
            var13[0] = (byte)(var14 >> 24 & 255);
            var0.update(var13);
            var0.doFinal(var10, 0);
            System.arraycopy(var10, 0, var11, 0, var10.length);

            for(int var15 = 2; var15 <= var3; ++var15) {
               var0.update(var10);
               var0.doFinal(var10, 0);

               for(int var16 = 0; var16 < var10.length; ++var16) {
                  var11[var16] ^= var10[var16];
               }
            }

            if (var14 == var8) {
               System.arraycopy(var11, 0, var6, (var14 - 1) * var7, var9);
            } else {
               System.arraycopy(var11, 0, var6, (var14 - 1) * var7, var7);
            }
         }

         return var6;
      } catch (GeneralSecurityException var17) {
         throw new RuntimeException("Error deriving PBKDF2 keys");
      }
   }

   public byte[] getEncoded() {
      return (byte[])this.key.clone();
   }

   public String getAlgorithm() {
      return "PBKDF2With" + this.prf.getAlgorithm();
   }

   public int getIterationCount() {
      return this.iterCount;
   }

   public char[] getPassword() {
      return (char[])this.passwd.clone();
   }

   public byte[] getSalt() {
      return (byte[])this.salt.clone();
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
         if (!var2.getAlgorithm().equalsIgnoreCase(this.getAlgorithm())) {
            return false;
         } else if (!var2.getFormat().equalsIgnoreCase("RAW")) {
            return false;
         } else {
            byte[] var3 = var2.getEncoded();
            boolean var4 = Arrays.equals(this.key, var2.getEncoded());
            Arrays.fill(var3, (byte)0);
            return var4;
         }
      }
   }

   private Object writeReplace() throws ObjectStreamException {
      return new KeyRep(Type.SECRET, this.getAlgorithm(), this.getFormat(), this.getEncoded());
   }

   protected void finalize() throws Throwable {
      try {
         if (this.passwd != null) {
            Arrays.fill(this.passwd, '0');
            this.passwd = null;
         }

         if (this.key != null) {
            Arrays.fill(this.key, (byte)0);
            this.key = null;
         }
      } finally {
         super.finalize();
      }

   }
}
