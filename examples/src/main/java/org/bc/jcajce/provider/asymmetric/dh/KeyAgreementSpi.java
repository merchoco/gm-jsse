package org.bc.jcajce.provider.asymmetric.dh;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bc.crypto.params.DESParameters;
import org.bc.util.Integers;
import org.bc.util.Strings;

public class KeyAgreementSpi extends javax.crypto.KeyAgreementSpi {
   private BigInteger x;
   private BigInteger p;
   private BigInteger g;
   private BigInteger result;
   private static final Hashtable algorithms = new Hashtable();

   static {
      Integer var0 = Integers.valueOf(64);
      Integer var1 = Integers.valueOf(192);
      Integer var2 = Integers.valueOf(128);
      Integer var3 = Integers.valueOf(256);
      algorithms.put("DES", var0);
      algorithms.put("DESEDE", var1);
      algorithms.put("BLOWFISH", var2);
      algorithms.put("AES", var3);
   }

   private byte[] bigIntToBytes(BigInteger var1) {
      byte[] var2 = var1.toByteArray();
      if (var2[0] == 0) {
         byte[] var3 = new byte[var2.length - 1];
         System.arraycopy(var2, 1, var3, 0, var3.length);
         return var3;
      } else {
         return var2;
      }
   }

   protected Key engineDoPhase(Key var1, boolean var2) throws InvalidKeyException, IllegalStateException {
      if (this.x == null) {
         throw new IllegalStateException("Diffie-Hellman not initialised.");
      } else if (!(var1 instanceof DHPublicKey)) {
         throw new InvalidKeyException("DHKeyAgreement doPhase requires DHPublicKey");
      } else {
         DHPublicKey var3 = (DHPublicKey)var1;
         if (var3.getParams().getG().equals(this.g) && var3.getParams().getP().equals(this.p)) {
            if (var2) {
               this.result = ((DHPublicKey)var1).getY().modPow(this.x, this.p);
               return null;
            } else {
               this.result = ((DHPublicKey)var1).getY().modPow(this.x, this.p);
               return new BCDHPublicKey(this.result, var3.getParams());
            }
         } else {
            throw new InvalidKeyException("DHPublicKey not for this KeyAgreement!");
         }
      }
   }

   protected byte[] engineGenerateSecret() throws IllegalStateException {
      if (this.x == null) {
         throw new IllegalStateException("Diffie-Hellman not initialised.");
      } else {
         return this.bigIntToBytes(this.result);
      }
   }

   protected int engineGenerateSecret(byte[] var1, int var2) throws IllegalStateException, ShortBufferException {
      if (this.x == null) {
         throw new IllegalStateException("Diffie-Hellman not initialised.");
      } else {
         byte[] var3 = this.bigIntToBytes(this.result);
         if (var1.length - var2 < var3.length) {
            throw new ShortBufferException("DHKeyAgreement - buffer too short");
         } else {
            System.arraycopy(var3, 0, var1, var2, var3.length);
            return var3.length;
         }
      }
   }

   protected SecretKey engineGenerateSecret(String var1) {
      if (this.x == null) {
         throw new IllegalStateException("Diffie-Hellman not initialised.");
      } else {
         String var2 = Strings.toUpperCase(var1);
         byte[] var3 = this.bigIntToBytes(this.result);
         if (algorithms.containsKey(var2)) {
            Integer var4 = (Integer)algorithms.get(var2);
            byte[] var5 = new byte[var4 / 8];
            System.arraycopy(var3, 0, var5, 0, var5.length);
            if (var2.startsWith("DES")) {
               DESParameters.setOddParity(var5);
            }

            return new SecretKeySpec(var5, var1);
         } else {
            return new SecretKeySpec(var3, var1);
         }
      }
   }

   protected void engineInit(Key var1, AlgorithmParameterSpec var2, SecureRandom var3) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (!(var1 instanceof DHPrivateKey)) {
         throw new InvalidKeyException("DHKeyAgreement requires DHPrivateKey for initialisation");
      } else {
         DHPrivateKey var4 = (DHPrivateKey)var1;
         if (var2 != null) {
            if (!(var2 instanceof DHParameterSpec)) {
               throw new InvalidAlgorithmParameterException("DHKeyAgreement only accepts DHParameterSpec");
            }

            DHParameterSpec var5 = (DHParameterSpec)var2;
            this.p = var5.getP();
            this.g = var5.getG();
         } else {
            this.p = var4.getParams().getP();
            this.g = var4.getParams().getG();
         }

         this.x = this.result = var4.getX();
      }
   }

   protected void engineInit(Key var1, SecureRandom var2) throws InvalidKeyException {
      if (!(var1 instanceof DHPrivateKey)) {
         throw new InvalidKeyException("DHKeyAgreement requires DHPrivateKey");
      } else {
         DHPrivateKey var3 = (DHPrivateKey)var1;
         this.p = var3.getParams().getP();
         this.g = var3.getParams().getG();
         this.x = this.result = var3.getX();
      }
   }
}
