package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;

public final class PBKDF2HmacSHA1Factory extends SecretKeyFactorySpi {
   protected SecretKey engineGenerateSecret(KeySpec var1) throws InvalidKeySpecException {
      if (!(var1 instanceof PBEKeySpec)) {
         throw new InvalidKeySpecException("Invalid key spec");
      } else {
         PBEKeySpec var2 = (PBEKeySpec)var1;
         return new PBKDF2KeyImpl(var2, "HmacSHA1");
      }
   }

   protected KeySpec engineGetKeySpec(SecretKey var1, Class var2) throws InvalidKeySpecException {
      if (var1 instanceof javax.crypto.interfaces.PBEKey) {
         if (var2 != null && PBEKeySpec.class.isAssignableFrom(var2)) {
            javax.crypto.interfaces.PBEKey var3 = (javax.crypto.interfaces.PBEKey)var1;
            return new PBEKeySpec(var3.getPassword(), var3.getSalt(), var3.getIterationCount(), var3.getEncoded().length * 8);
         } else {
            throw new InvalidKeySpecException("Invalid key spec");
         }
      } else {
         throw new InvalidKeySpecException("Invalid key format/algorithm");
      }
   }

   protected SecretKey engineTranslateKey(SecretKey var1) throws InvalidKeyException {
      if (var1 != null && var1.getAlgorithm().equalsIgnoreCase("PBKDF2WithHmacSHA1") && var1.getFormat().equalsIgnoreCase("RAW")) {
         if (var1 instanceof PBKDF2KeyImpl) {
            return var1;
         }

         if (var1 instanceof javax.crypto.interfaces.PBEKey) {
            javax.crypto.interfaces.PBEKey var2 = (javax.crypto.interfaces.PBEKey)var1;

            try {
               PBEKeySpec var3 = new PBEKeySpec(var2.getPassword(), var2.getSalt(), var2.getIterationCount(), var2.getEncoded().length * 8);
               return new PBKDF2KeyImpl(var3, "HmacSHA1");
            } catch (InvalidKeySpecException var5) {
               InvalidKeyException var4 = new InvalidKeyException("Invalid key component(s)");
               var4.initCause(var5);
               throw var4;
            }
         }
      }

      throw new InvalidKeyException("Invalid key format/algorithm");
   }
}
