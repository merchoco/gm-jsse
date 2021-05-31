package cn.gmssl.com.sun.crypto.provider;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class DHKeyAgreement extends KeyAgreementSpi {
   private boolean generateSecret = false;
   private BigInteger init_p = null;
   private BigInteger init_g = null;
   private BigInteger x;
   private BigInteger y;

   public DHKeyAgreement() {
      this.x = BigInteger.ZERO;
      this.y = BigInteger.ZERO;
   }

   protected void engineInit(Key var1, SecureRandom var2) throws InvalidKeyException {
      try {
         this.engineInit(var1, (AlgorithmParameterSpec)null, var2);
      } catch (InvalidAlgorithmParameterException var4) {
         ;
      }

   }

   protected void engineInit(Key var1, AlgorithmParameterSpec var2, SecureRandom var3) throws InvalidKeyException, InvalidAlgorithmParameterException {
      this.generateSecret = false;
      this.init_p = null;
      this.init_g = null;
      if (var2 != null && !(var2 instanceof DHParameterSpec)) {
         throw new InvalidAlgorithmParameterException("Diffie-Hellman parameters expected");
      } else if (!(var1 instanceof javax.crypto.interfaces.DHPrivateKey)) {
         throw new InvalidKeyException("Diffie-Hellman private key expected");
      } else {
         javax.crypto.interfaces.DHPrivateKey var4 = (javax.crypto.interfaces.DHPrivateKey)var1;
         if (var2 != null) {
            this.init_p = ((DHParameterSpec)var2).getP();
            this.init_g = ((DHParameterSpec)var2).getG();
         }

         BigInteger var5 = var4.getParams().getP();
         BigInteger var6 = var4.getParams().getG();
         if (this.init_p != null && var5 != null && !this.init_p.equals(var5)) {
            throw new InvalidKeyException("Incompatible parameters");
         } else if (this.init_g != null && var6 != null && !this.init_g.equals(var6)) {
            throw new InvalidKeyException("Incompatible parameters");
         } else if ((this.init_p != null || var5 != null) && (this.init_g != null || var6 != null)) {
            this.init_p = var5;
            this.init_g = var6;
            this.x = var4.getX();
         } else {
            throw new InvalidKeyException("Missing parameters");
         }
      }
   }

   protected Key engineDoPhase(Key var1, boolean var2) throws InvalidKeyException, IllegalStateException {
      if (!(var1 instanceof javax.crypto.interfaces.DHPublicKey)) {
         throw new InvalidKeyException("Diffie-Hellman public key expected");
      } else {
         javax.crypto.interfaces.DHPublicKey var3 = (javax.crypto.interfaces.DHPublicKey)var1;
         if (this.init_p != null && this.init_g != null) {
            BigInteger var4 = var3.getParams().getP();
            BigInteger var5 = var3.getParams().getG();
            if (var4 != null && !this.init_p.equals(var4)) {
               throw new InvalidKeyException("Incompatible parameters");
            } else if (var5 != null && !this.init_g.equals(var5)) {
               throw new InvalidKeyException("Incompatible parameters");
            } else {
               this.y = var3.getY();
               this.generateSecret = true;
               if (!var2) {
                  byte[] var6 = this.engineGenerateSecret();
                  return new DHPublicKey(new BigInteger(1, var6), this.init_p, this.init_g);
               } else {
                  return null;
               }
            }
         } else {
            throw new IllegalStateException("Not initialized");
         }
      }
   }

   protected byte[] engineGenerateSecret() throws IllegalStateException {
      if (!this.generateSecret) {
         throw new IllegalStateException("Key agreement has not been completed yet");
      } else {
         this.generateSecret = false;
         BigInteger var1 = this.init_p;
         BigInteger var2 = this.y.modPow(this.x, var1);
         byte[] var3 = var2.toByteArray();
         if (var2.bitLength() % 8 == 0) {
            byte[] var4 = new byte[var3.length - 1];
            System.arraycopy(var3, 1, var4, 0, var4.length);
            return var4;
         } else {
            return var3;
         }
      }
   }

   protected int engineGenerateSecret(byte[] var1, int var2) throws IllegalStateException, ShortBufferException {
      if (!this.generateSecret) {
         throw new IllegalStateException("Key agreement has not been completed yet");
      } else if (var1 == null) {
         throw new ShortBufferException("No buffer provided for shared secret");
      } else {
         BigInteger var3 = this.init_p;
         byte[] var4 = this.y.modPow(this.x, var3).toByteArray();
         if (var4.length << 3 != var3.bitLength()) {
            if (var1.length - var2 < var4.length - 1) {
               throw new ShortBufferException("Buffer too short for shared secret");
            } else {
               System.arraycopy(var4, 1, var1, var2, var4.length - 1);
               this.generateSecret = false;
               return var4.length - 1;
            }
         } else if (var1.length - var2 < var4.length) {
            throw new ShortBufferException("Buffer too short to hold shared secret");
         } else {
            System.arraycopy(var4, 0, var1, var2, var4.length);
            this.generateSecret = false;
            return var4.length;
         }
      }
   }

   protected SecretKey engineGenerateSecret(String var1) throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
      if (var1 == null) {
         throw new NoSuchAlgorithmException("null algorithm");
      } else {
         byte[] var2 = this.engineGenerateSecret();
         if (var1.equalsIgnoreCase("DES")) {
            return new DESKey(var2);
         } else if (!var1.equalsIgnoreCase("DESede") && !var1.equalsIgnoreCase("TripleDES")) {
            int var3;
            SecretKeySpec var4;
            if (var1.equalsIgnoreCase("Blowfish")) {
               var3 = var2.length;
               if (var3 >= 56) {
                  var3 = 56;
               }

               var4 = new SecretKeySpec(var2, 0, var3, "Blowfish");
               return var4;
            } else if (!var1.equalsIgnoreCase("AES")) {
               if (var1.equals("TlsPremasterSecret")) {
                  return new SecretKeySpec(var2, "TlsPremasterSecret");
               } else {
                  throw new NoSuchAlgorithmException("Unsupported secret key algorithm: " + var1);
               }
            } else {
               var3 = var2.length;
               var4 = null;

               for(int var5 = AESConstants.AES_KEYSIZES.length - 1; var4 == null && var5 >= 0; --var5) {
                  if (var3 >= AESConstants.AES_KEYSIZES[var5]) {
                     var3 = AESConstants.AES_KEYSIZES[var5];
                     var4 = new SecretKeySpec(var2, 0, var3, "AES");
                  }
               }

               if (var4 == null) {
                  throw new InvalidKeyException("Key material is too short");
               } else {
                  return var4;
               }
            }
         } else {
            return new DESedeKey(var2);
         }
      }
   }
}
