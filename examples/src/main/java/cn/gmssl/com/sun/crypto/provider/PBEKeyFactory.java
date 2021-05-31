package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.HashSet;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;

abstract class PBEKeyFactory extends SecretKeyFactorySpi {
   private String type;
   private static HashSet<String> validTypes = new HashSet(4);

   static {
      validTypes.add("PBEWithMD5AndDES".toUpperCase());
      validTypes.add("PBEWithSHA1AndDESede".toUpperCase());
      validTypes.add("PBEWithSHA1AndRC2_40".toUpperCase());
      validTypes.add("PBEWithMD5AndTripleDES".toUpperCase());
   }

   private PBEKeyFactory(String var1) {
      this.type = var1;
   }

   protected SecretKey engineGenerateSecret(KeySpec var1) throws InvalidKeySpecException {
      if (!(var1 instanceof PBEKeySpec)) {
         throw new InvalidKeySpecException("Invalid key spec");
      } else {
         return new PBEKey((PBEKeySpec)var1, this.type);
      }
   }

   protected KeySpec engineGetKeySpec(SecretKey var1, Class var2) throws InvalidKeySpecException {
      if (var1 instanceof SecretKey && validTypes.contains(var1.getAlgorithm().toUpperCase()) && var1.getFormat().equalsIgnoreCase("RAW")) {
         if (var2 != null && PBEKeySpec.class.isAssignableFrom(var2)) {
            byte[] var3 = var1.getEncoded();
            char[] var4 = new char[var3.length];

            for(int var5 = 0; var5 < var4.length; ++var5) {
               var4[var5] = (char)(var3[var5] & 127);
            }

            PBEKeySpec var6 = new PBEKeySpec(var4);
            Arrays.fill(var4, ' ');
            Arrays.fill(var3, (byte)0);
            return var6;
         } else {
            throw new InvalidKeySpecException("Invalid key spec");
         }
      } else {
         throw new InvalidKeySpecException("Invalid key format/algorithm");
      }
   }

   protected SecretKey engineTranslateKey(SecretKey var1) throws InvalidKeyException {
      try {
         if (var1 != null && validTypes.contains(var1.getAlgorithm().toUpperCase()) && var1.getFormat().equalsIgnoreCase("RAW")) {
            if (var1 instanceof PBEKey) {
               return var1;
            } else {
               PBEKeySpec var2 = (PBEKeySpec)this.engineGetKeySpec(var1, PBEKeySpec.class);
               return this.engineGenerateSecret(var2);
            }
         } else {
            throw new InvalidKeyException("Invalid key format/algorithm");
         }
      } catch (InvalidKeySpecException var3) {
         throw new InvalidKeyException("Cannot translate key: " + var3.getMessage());
      }
   }

   // $FF: synthetic method
   PBEKeyFactory(String var1, PBEKeyFactory var2) {
      this(var1);
   }

   public static final class PBEWithMD5AndDES extends PBEKeyFactory {
      public PBEWithMD5AndDES() {
         super("PBEWithMD5AndDES", (PBEKeyFactory)null);
      }
   }

   public static final class PBEWithMD5AndTripleDES extends PBEKeyFactory {
      public PBEWithMD5AndTripleDES() {
         super("PBEWithMD5AndTripleDES", (PBEKeyFactory)null);
      }
   }

   public static final class PBEWithSHA1AndDESede extends PBEKeyFactory {
      public PBEWithSHA1AndDESede() {
         super("PBEWithSHA1AndDESede", (PBEKeyFactory)null);
      }
   }

   public static final class PBEWithSHA1AndRC2_40 extends PBEKeyFactory {
      public PBEWithSHA1AndRC2_40() {
         super("PBEWithSHA1AndRC2_40", (PBEKeyFactory)null);
      }
   }
}
