package cn.gmssl.sun.security.ssl;

import cn.gmssl.crypto.SM2KeyExchangeParams;
import cn.gmssl.crypto.impl.sm2.SM2KeyExchangeUtil;
import cn.gmssl.crypto.impl.sm2.SM2Util;
import cn.gmssl.jsse.provider.GMConf;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import org.bc.jce.interfaces.ECPrivateKey;
import org.bc.jce.interfaces.ECPublicKey;
import org.bc.jce.spec.ECParameterSpec;
import org.bc.jce.spec.ECPublicKeySpec;
import org.bc.math.ec.ECPoint;

public class SM2Crypt {
   private BigInteger random = null;
   private ECPublicKey publicKey = null;
   private ECPrivateKey privateKey = null;
   private ECPublicKey peerPublicKey = null;
   private boolean active = false;
   public StringBuilder sb = null;

   public SM2Crypt(PublicKey var1, PrivateKey var2, SecureRandom var3, boolean var4) {
      try {
         if (var1 instanceof ECPublicKey) {
            this.publicKey = (ECPublicKey)var1;
         } else {
            this.publicKey = SM2Util.toTsgECPublicKey(var1);
         }

         if (var2 instanceof ECPrivateKey) {
            this.privateKey = (ECPrivateKey)var2;
         } else {
            this.privateKey = SM2Util.toTsgECPrivateKey(var2);
         }

         this.active = var4;
         if (GMConf.debug) {
            System.out.println("this.publicKey=" + this.publicKey);
            System.out.println("this.publicKey.getParameters()=" + this.publicKey.getParameters());
         }

         this.random = SM2KeyExchangeUtil.generateRandom(this.publicKey.getParameters().getN(), var3);
      } catch (Exception var6) {
         var6.printStackTrace();
         throw new RuntimeException(var6);
      }
   }

   public SM2Crypt(String var1, SecureRandom var2, boolean var3) {
      try {
         KeyPairGenerator var4 = JsseJce.getKeyPairGenerator("SM2");
         ECGenParameterSpec var5 = new ECGenParameterSpec(var1);
         var4.initialize(var5, var2);
         KeyPair var6 = var4.generateKeyPair();
         this.privateKey = (ECPrivateKey)var6.getPrivate();
         this.publicKey = (ECPublicKey)var6.getPublic();
         this.random = SM2KeyExchangeUtil.generateRandom(this.publicKey.getParameters().getN(), var2);
         this.active = var3;
      } catch (GeneralSecurityException var7) {
         var7.printStackTrace();
         throw new RuntimeException("Could not generate SM2 keypair", var7);
      }
   }

   public void setPeerPublicKey(PublicKey var1) {
      try {
         if (var1 instanceof ECPublicKey) {
            this.peerPublicKey = (ECPublicKey)var1;
         } else {
            this.peerPublicKey = SM2Util.toTsgECPublicKey(var1);
         }

      } catch (Exception var3) {
         throw new RuntimeException(var3);
      }
   }

   public void setRandom(BigInteger var1) {
      this.random = var1;
   }

   public byte[] getRPointEncoded() {
      ECPoint var1 = SM2KeyExchangeUtil.generateR(this.publicKey, this.random);
      return var1.getEncoded();
   }

   public SecretKey getAgreedSecret(byte[] var1, byte[] var2, byte[] var3) {
      try {
         ECParameterSpec var4 = this.peerPublicKey.getParameters();
         ECPoint var5 = var4.getCurve().decodePoint(var1);
         ECPublicKeySpec var6 = new ECPublicKeySpec(var5, var4);
         KeyFactory var7 = KeyFactory.getInstance("SM2");
         ECPublicKey var8 = (ECPublicKey)var7.generatePublic(var6);
         return this.getAgreedSecret((PublicKey)var8, var2, var3);
      } catch (Exception var9) {
         var9.printStackTrace();
         throw new RuntimeException(var9);
      }
   }

   public SecretKey getAgreedSecret(PublicKey var1, byte[] var2, byte[] var3) {
      try {
         ECPublicKey var4 = null;
         if (var1 instanceof ECPublicKey) {
            var4 = (ECPublicKey)var1;
         } else {
            var4 = SM2Util.toTsgECPublicKey(var1);
         }

         KeyAgreement var5 = KeyAgreement.getInstance("SM2");
         SM2KeyExchangeParams var6 = new SM2KeyExchangeParams(this.publicKey, this.peerPublicKey, this.random, var2, var3, 48, this.active);
         var5.init(this.privateKey, var6, (SecureRandom)null);
         return (SecretKey)var5.doPhase(var4, true);
      } catch (Exception var7) {
         var7.printStackTrace();
         throw new RuntimeException(var7);
      }
   }
}
