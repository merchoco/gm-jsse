package cn.gmssl.crypto.impl.sm2;

import cn.gmssl.crypto.SM2KeyExchangeParams;
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
import javax.crypto.spec.SecretKeySpec;
import org.bc.jce.interfaces.ECPrivateKey;
import org.bc.jce.interfaces.ECPublicKey;
import org.bc.math.ec.ECPoint;

public class SM2KeyAgreement extends KeyAgreementSpi {
   private ECPrivateKey privateKey = null;
   private ECPublicKey publicKey = null;
   private ECPublicKey publicRemote = null;
   private BigInteger random = null;
   private byte[] idLocal = null;
   private byte[] idRemote = null;
   private boolean active = false;
   private int keyLength = 0;
   private byte[] shareKey = null;

   protected void engineInit(Key var1, SecureRandom var2) throws InvalidKeyException {
      throw new UnsupportedOperationException();
   }

   protected void engineInit(Key var1, AlgorithmParameterSpec var2, SecureRandom var3) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (!(var2 instanceof SM2KeyExchangeParams)) {
         throw new InvalidAlgorithmParameterException("SM2 key agreement requires SM2KeyExchangeParams for init");
      } else if (var1 instanceof ECPrivateKey) {
         this.privateKey = (ECPrivateKey)var1;
         SM2KeyExchangeParams var4 = (SM2KeyExchangeParams)var2;
         this.random = var4.getRandom();
         if (this.random == null) {
            throw new InvalidAlgorithmParameterException("random cannot be null");
         } else {
            this.publicKey = (ECPublicKey)var4.getPublicKey();
            if (this.publicKey == null) {
               throw new InvalidAlgorithmParameterException("publicKey cannot be null");
            } else {
               this.publicRemote = (ECPublicKey)var4.getPeerPublicKey();
               if (this.publicRemote == null) {
                  throw new InvalidAlgorithmParameterException("peerPublicKey cannot be null");
               } else {
                  this.idLocal = var4.getIdLocal();
                  if (this.idLocal == null) {
                     throw new InvalidAlgorithmParameterException("idLocal cannot be null");
                  } else {
                     this.idRemote = var4.getIdRemote();
                     if (this.idRemote == null) {
                        throw new InvalidAlgorithmParameterException("idRemote cannot be null");
                     } else {
                        this.keyLength = var4.getKeyLength();
                        this.active = var4.isActive();
                     }
                  }
               }
            }
         }
      } else {
         throw new InvalidKeyException("SM2 key agreement requires ECPrivateKey for initialisation");
      }
   }

   protected Key engineDoPhase(Key var1, boolean var2) throws InvalidKeyException, IllegalStateException {
      ECPoint var3 = null;
      if (var1 instanceof ECPublicKey) {
         var3 = ((ECPublicKey)var1).getQ();
      }

      try {
         this.shareKey = SM2KeyExchangeUtil.generateK(this.publicKey, this.privateKey, this.publicRemote, this.random, var3, this.idLocal, this.idRemote, this.active, this.keyLength);
      } catch (Exception var5) {
         throw new RuntimeException(var5);
      }

      return new SecretKeySpec(this.shareKey, "SM2Key");
   }

   protected byte[] engineGenerateSecret() throws IllegalStateException {
      return this.shareKey;
   }

   protected int engineGenerateSecret(byte[] var1, int var2) throws IllegalStateException, ShortBufferException {
      throw new UnsupportedOperationException();
   }

   protected SecretKey engineGenerateSecret(String var1) throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
      return new SecretKeySpec(this.shareKey, var1);
   }
}
