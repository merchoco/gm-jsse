package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

final class KeyGeneratorCore {
   private final String name;
   private final int defaultKeySize;
   private int keySize;
   private SecureRandom random;

   KeyGeneratorCore(String var1, int var2) {
      this.name = var1;
      this.defaultKeySize = var2;
      this.implInit((SecureRandom)null);
   }

   void implInit(SecureRandom var1) {
      this.keySize = this.defaultKeySize;
      this.random = var1;
   }

   void implInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      throw new InvalidAlgorithmParameterException(this.name + " key generation does not take any parameters");
   }

   void implInit(int var1, SecureRandom var2) {
      if (var1 < 40) {
         throw new InvalidParameterException("Key length must be at least 40 bits");
      } else {
         this.keySize = var1;
         this.random = var2;
      }
   }

   SecretKey implGenerateKey() {
      if (this.random == null) {
         this.random = SunJCE.RANDOM;
      }

      byte[] var1 = new byte[this.keySize + 7 >> 3];
      this.random.nextBytes(var1);
      return new SecretKeySpec(var1, this.name);
   }

   public static final class ARCFOURKeyGenerator extends KeyGeneratorSpi {
      private final KeyGeneratorCore core = new KeyGeneratorCore("ARCFOUR", 128);

      protected void engineInit(SecureRandom var1) {
         this.core.implInit(var1);
      }

      protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
         this.core.implInit(var1, var2);
      }

      protected void engineInit(int var1, SecureRandom var2) {
         if (var1 >= 40 && var1 <= 1024) {
            this.core.implInit(var1, var2);
         } else {
            throw new InvalidParameterException("Key length for ARCFOUR must be between 40 and 1024 bits");
         }
      }

      protected SecretKey engineGenerateKey() {
         return this.core.implGenerateKey();
      }
   }

   public static final class HmacSHA256KG extends KeyGeneratorSpi {
      private final KeyGeneratorCore core = new KeyGeneratorCore("HmacSHA256", 256);

      protected void engineInit(SecureRandom var1) {
         this.core.implInit(var1);
      }

      protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
         this.core.implInit(var1, var2);
      }

      protected void engineInit(int var1, SecureRandom var2) {
         this.core.implInit(var1, var2);
      }

      protected SecretKey engineGenerateKey() {
         return this.core.implGenerateKey();
      }
   }

   public static final class HmacSHA384KG extends KeyGeneratorSpi {
      private final KeyGeneratorCore core = new KeyGeneratorCore("HmacSHA384", 384);

      protected void engineInit(SecureRandom var1) {
         this.core.implInit(var1);
      }

      protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
         this.core.implInit(var1, var2);
      }

      protected void engineInit(int var1, SecureRandom var2) {
         this.core.implInit(var1, var2);
      }

      protected SecretKey engineGenerateKey() {
         return this.core.implGenerateKey();
      }
   }

   public static final class HmacSHA512KG extends KeyGeneratorSpi {
      private final KeyGeneratorCore core = new KeyGeneratorCore("HmacSHA512", 512);

      protected void engineInit(SecureRandom var1) {
         this.core.implInit(var1);
      }

      protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
         this.core.implInit(var1, var2);
      }

      protected void engineInit(int var1, SecureRandom var2) {
         this.core.implInit(var1, var2);
      }

      protected SecretKey engineGenerateKey() {
         return this.core.implGenerateKey();
      }
   }

   public static final class RC2KeyGenerator extends KeyGeneratorSpi {
      private final KeyGeneratorCore core = new KeyGeneratorCore("RC2", 128);

      protected void engineInit(SecureRandom var1) {
         this.core.implInit(var1);
      }

      protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
         this.core.implInit(var1, var2);
      }

      protected void engineInit(int var1, SecureRandom var2) {
         if (var1 >= 40 && var1 <= 1024) {
            this.core.implInit(var1, var2);
         } else {
            throw new InvalidParameterException("Key length for RC2 must be between 40 and 1024 bits");
         }
      }

      protected SecretKey engineGenerateKey() {
         return this.core.implGenerateKey();
      }
   }
}
