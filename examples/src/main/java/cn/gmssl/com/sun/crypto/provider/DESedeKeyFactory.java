package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.DESedeKeySpec;

public final class DESedeKeyFactory extends SecretKeyFactorySpi {
   protected SecretKey engineGenerateSecret(KeySpec var1) throws InvalidKeySpecException {
      DESedeKey var2 = null;

      try {
         if (!(var1 instanceof DESedeKeySpec)) {
            throw new InvalidKeySpecException("Inappropriate key specification");
         }

         DESedeKeySpec var3 = (DESedeKeySpec)var1;
         var2 = new DESedeKey(var3.getKey());
      } catch (InvalidKeyException var4) {
         ;
      }

      return var2;
   }

   protected KeySpec engineGetKeySpec(SecretKey var1, Class var2) throws InvalidKeySpecException {
      try {
         if (var1 instanceof SecretKey && var1.getAlgorithm().equalsIgnoreCase("DESede") && var1.getFormat().equalsIgnoreCase("RAW")) {
            if (DESedeKeySpec.class.isAssignableFrom(var2)) {
               return new DESedeKeySpec(var1.getEncoded());
            } else {
               throw new InvalidKeySpecException("Inappropriate key specification");
            }
         } else {
            throw new InvalidKeySpecException("Inappropriate key format/algorithm");
         }
      } catch (InvalidKeyException var4) {
         throw new InvalidKeySpecException("Secret key has wrong size");
      }
   }

   protected SecretKey engineTranslateKey(SecretKey var1) throws InvalidKeyException {
      try {
         if (var1 != null && var1.getAlgorithm().equalsIgnoreCase("DESede") && var1.getFormat().equalsIgnoreCase("RAW")) {
            if (var1 instanceof DESedeKey) {
               return var1;
            } else {
               DESedeKeySpec var2 = (DESedeKeySpec)this.engineGetKeySpec(var1, DESedeKeySpec.class);
               return this.engineGenerateSecret(var2);
            }
         } else {
            throw new InvalidKeyException("Inappropriate key format/algorithm");
         }
      } catch (InvalidKeySpecException var3) {
         throw new InvalidKeyException("Cannot translate key");
      }
   }
}
