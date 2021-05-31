package cn.gmssl.sun.security.ssl;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

final class DHCrypt {
   private BigInteger modulus;
   private BigInteger base;
   private PrivateKey privateKey;
   private BigInteger publicValue;

   DHCrypt(int var1, SecureRandom var2) {
      try {
         KeyPairGenerator var3 = JsseJce.getKeyPairGenerator("DiffieHellman");
         var3.initialize(var1, var2);
         KeyPair var4 = var3.generateKeyPair();
         this.privateKey = var4.getPrivate();
         DHPublicKeySpec var5 = getDHPublicKeySpec(var4.getPublic());
         this.publicValue = var5.getY();
         this.modulus = var5.getP();
         this.base = var5.getG();
      } catch (GeneralSecurityException var6) {
         throw new RuntimeException("Could not generate DH keypair", var6);
      }
   }

   DHCrypt(BigInteger var1, BigInteger var2, SecureRandom var3) {
      this.modulus = var1;
      this.base = var2;

      try {
         KeyPairGenerator var4 = JsseJce.getKeyPairGenerator("DiffieHellman");
         DHParameterSpec var5 = new DHParameterSpec(var1, var2);
         var4.initialize(var5, var3);
         KeyPair var6 = var4.generateKeyPair();
         this.privateKey = var6.getPrivate();
         DHPublicKeySpec var7 = getDHPublicKeySpec(var6.getPublic());
         this.publicValue = var7.getY();
      } catch (GeneralSecurityException var8) {
         throw new RuntimeException("Could not generate DH keypair", var8);
      }
   }

   static DHPublicKeySpec getDHPublicKeySpec(PublicKey var0) {
      if (var0 instanceof DHPublicKey) {
         DHPublicKey var4 = (DHPublicKey)var0;
         DHParameterSpec var2 = var4.getParams();
         return new DHPublicKeySpec(var4.getY(), var2.getP(), var2.getG());
      } else {
         try {
            KeyFactory var1 = JsseJce.getKeyFactory("DH");
            return (DHPublicKeySpec)var1.getKeySpec(var0, DHPublicKeySpec.class);
         } catch (Exception var3) {
            throw new RuntimeException(var3);
         }
      }
   }

   BigInteger getModulus() {
      return this.modulus;
   }

   BigInteger getBase() {
      return this.base;
   }

   BigInteger getPublicKey() {
      return this.publicValue;
   }

   SecretKey getAgreedSecret(BigInteger var1) {
      try {
         KeyFactory var2 = JsseJce.getKeyFactory("DiffieHellman");
         DHPublicKeySpec var3 = new DHPublicKeySpec(var1, this.modulus, this.base);
         PublicKey var4 = var2.generatePublic(var3);
         KeyAgreement var5 = JsseJce.getKeyAgreement("DiffieHellman");
         var5.init(this.privateKey);
         var5.doPhase(var4, true);
         return var5.generateSecret("TlsPremasterSecret");
      } catch (GeneralSecurityException var6) {
         throw new RuntimeException("Could not generate secret", var6);
      }
   }
}
