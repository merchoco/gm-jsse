package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.DESKeySpec;

public final class DESKeyFactory extends SecretKeyFactorySpi {
   protected SecretKey engineGenerateSecret(KeySpec var1) throws InvalidKeySpecException {
      DESKey var2 = null;

      try {
         if (!(var1 instanceof DESKeySpec)) {
            throw new InvalidKeySpecException("Inappropriate key specification");
         }

         DESKeySpec var3 = (DESKeySpec)var1;
         var2 = new DESKey(var3.getKey());
      } catch (InvalidKeyException var4) {
         ;
      }

      return var2;
   }

   protected KeySpec engineGetKeySpec(SecretKey var1, Class var2) throws InvalidKeySpecException {
      try {
         if (var1 instanceof SecretKey && var1.getAlgorithm().equalsIgnoreCase("DES") && var1.getFormat().equalsIgnoreCase("RAW")) {
            if (var2 != null && DESKeySpec.class.isAssignableFrom(var2)) {
               return new DESKeySpec(var1.getEncoded());
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
         if (var1 != null && var1.getAlgorithm().equalsIgnoreCase("DES") && var1.getFormat().equalsIgnoreCase("RAW")) {
            if (var1 instanceof DESKey) {
               return var1;
            } else {
               DESKeySpec var2 = (DESKeySpec)this.engineGetKeySpec(var1, DESKeySpec.class);
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
