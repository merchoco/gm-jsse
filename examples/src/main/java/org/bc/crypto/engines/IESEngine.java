package org.bc.crypto.engines;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.bc.crypto.BasicAgreement;
import org.bc.crypto.BufferedBlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DerivationFunction;
import org.bc.crypto.EphemeralKeyPair;
import org.bc.crypto.InvalidCipherTextException;
import org.bc.crypto.KeyParser;
import org.bc.crypto.Mac;
import org.bc.crypto.generators.EphemeralKeyPairGenerator;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.IESParameters;
import org.bc.crypto.params.IESWithCipherParameters;
import org.bc.crypto.params.KDFParameters;
import org.bc.crypto.params.KeyParameter;
import org.bc.crypto.util.Pack;
import org.bc.util.Arrays;
import org.bc.util.BigIntegers;

public class IESEngine {
   BasicAgreement agree;
   DerivationFunction kdf;
   Mac mac;
   BufferedBlockCipher cipher;
   byte[] macBuf;
   boolean forEncryption;
   CipherParameters privParam;
   CipherParameters pubParam;
   IESParameters param;
   byte[] V;
   private EphemeralKeyPairGenerator keyPairGenerator;
   private KeyParser keyParser;

   public IESEngine(BasicAgreement var1, DerivationFunction var2, Mac var3) {
      this.agree = var1;
      this.kdf = var2;
      this.mac = var3;
      this.macBuf = new byte[var3.getMacSize()];
      this.cipher = null;
   }

   public IESEngine(BasicAgreement var1, DerivationFunction var2, Mac var3, BufferedBlockCipher var4) {
      this.agree = var1;
      this.kdf = var2;
      this.mac = var3;
      this.macBuf = new byte[var3.getMacSize()];
      this.cipher = var4;
   }

   public void init(boolean var1, CipherParameters var2, CipherParameters var3, CipherParameters var4) {
      this.forEncryption = var1;
      this.privParam = var2;
      this.pubParam = var3;
      this.param = (IESParameters)var4;
      this.V = new byte[0];
   }

   public void init(AsymmetricKeyParameter var1, CipherParameters var2, EphemeralKeyPairGenerator var3) {
      this.forEncryption = true;
      this.pubParam = var1;
      this.param = (IESParameters)var2;
      this.keyPairGenerator = var3;
   }

   public void init(AsymmetricKeyParameter var1, CipherParameters var2, KeyParser var3) {
      this.forEncryption = false;
      this.privParam = var1;
      this.param = (IESParameters)var2;
      this.keyParser = var3;
   }

   public BufferedBlockCipher getCipher() {
      return this.cipher;
   }

   public Mac getMac() {
      return this.mac;
   }

   private byte[] encryptBlock(byte[] var1, int var2, int var3) throws InvalidCipherTextException {
      Object var4 = null;
      Object var5 = null;
      Object var6 = null;
      Object var7 = null;
      int var8;
      byte[] var13;
      byte[] var14;
      byte[] var15;
      byte[] var16;
      if (this.cipher == null) {
         var15 = new byte[var3];
         var16 = new byte[this.param.getMacKeySize() / 8];
         var14 = new byte[var15.length + var16.length];
         this.kdf.generateBytes(var14, 0, var14.length);
         if (this.V.length != 0) {
            System.arraycopy(var14, 0, var16, 0, var16.length);
            System.arraycopy(var14, var16.length, var15, 0, var15.length);
         } else {
            System.arraycopy(var14, 0, var15, 0, var15.length);
            System.arraycopy(var14, var3, var16, 0, var16.length);
         }

         var13 = new byte[var3];

         for(int var9 = 0; var9 != var3; ++var9) {
            var13[var9] = (byte)(var1[var2 + var9] ^ var15[var9]);
         }

         var8 = var3;
      } else {
         var15 = new byte[((IESWithCipherParameters)this.param).getCipherKeySize() / 8];
         var16 = new byte[this.param.getMacKeySize() / 8];
         var14 = new byte[var15.length + var16.length];
         this.kdf.generateBytes(var14, 0, var14.length);
         System.arraycopy(var14, 0, var15, 0, var15.length);
         System.arraycopy(var14, var15.length, var16, 0, var16.length);
         this.cipher.init(true, new KeyParameter(var15));
         var13 = new byte[this.cipher.getOutputSize(var3)];
         var8 = this.cipher.processBytes(var1, var2, var3, var13, 0);
         var8 += this.cipher.doFinal(var13, var8);
      }

      byte[] var17 = this.param.getEncodingV();
      byte[] var10 = new byte[4];
      if (this.V.length != 0) {
         if (var17 == null) {
            Pack.intToBigEndian(0, var10, 0);
         } else {
            Pack.intToBigEndian(var17.length * 8, var10, 0);
         }
      }

      byte[] var11 = new byte[this.mac.getMacSize()];
      this.mac.init(new KeyParameter(var16));
      this.mac.update(var13, 0, var13.length);
      if (var17 != null) {
         this.mac.update(var17, 0, var17.length);
      }

      if (this.V.length != 0) {
         this.mac.update(var10, 0, var10.length);
      }

      this.mac.doFinal(var11, 0);
      byte[] var12 = new byte[this.V.length + var8 + var11.length];
      System.arraycopy(this.V, 0, var12, 0, this.V.length);
      System.arraycopy(var13, 0, var12, this.V.length, var8);
      System.arraycopy(var11, 0, var12, this.V.length + var8, var11.length);
      return var12;
   }

   private byte[] decryptBlock(byte[] var1, int var2, int var3) throws InvalidCipherTextException {
      Object var4 = null;
      Object var5 = null;
      Object var6 = null;
      Object var7 = null;
      int var8;
      byte[] var14;
      byte[] var15;
      byte[] var16;
      byte[] var17;
      if (this.cipher == null) {
         var16 = new byte[var3 - this.V.length - this.mac.getMacSize()];
         var17 = new byte[this.param.getMacKeySize() / 8];
         var15 = new byte[var16.length + var17.length];
         this.kdf.generateBytes(var15, 0, var15.length);
         if (this.V.length != 0) {
            System.arraycopy(var15, 0, var17, 0, var17.length);
            System.arraycopy(var15, var17.length, var16, 0, var16.length);
         } else {
            System.arraycopy(var15, 0, var16, 0, var16.length);
            System.arraycopy(var15, var16.length, var17, 0, var17.length);
         }

         var14 = new byte[var16.length];

         for(int var9 = 0; var9 != var16.length; ++var9) {
            var14[var9] = (byte)(var1[var2 + this.V.length + var9] ^ var16[var9]);
         }

         var8 = var16.length;
      } else {
         var16 = new byte[((IESWithCipherParameters)this.param).getCipherKeySize() / 8];
         var17 = new byte[this.param.getMacKeySize() / 8];
         var15 = new byte[var16.length + var17.length];
         this.kdf.generateBytes(var15, 0, var15.length);
         System.arraycopy(var15, 0, var16, 0, var16.length);
         System.arraycopy(var15, var16.length, var17, 0, var17.length);
         this.cipher.init(false, new KeyParameter(var16));
         var14 = new byte[this.cipher.getOutputSize(var3 - this.V.length - this.mac.getMacSize())];
         var8 = this.cipher.processBytes(var1, var2 + this.V.length, var3 - this.V.length - this.mac.getMacSize(), var14, 0);
         var8 += this.cipher.doFinal(var14, var8);
      }

      byte[] var18 = this.param.getEncodingV();
      byte[] var10 = new byte[4];
      if (this.V.length != 0) {
         if (var18 != null) {
            Pack.intToBigEndian(var18.length * 8, var10, 0);
         } else {
            Pack.intToBigEndian(0, var10, 0);
         }
      }

      byte[] var11 = new byte[this.mac.getMacSize()];
      System.arraycopy(var1, var2 + var3 - var11.length, var11, 0, var11.length);
      byte[] var12 = new byte[var11.length];
      this.mac.init(new KeyParameter(var17));
      this.mac.update(var1, var2 + this.V.length, var3 - this.V.length - var12.length);
      if (var18 != null) {
         this.mac.update(var18, 0, var18.length);
      }

      if (this.V.length != 0) {
         this.mac.update(var10, 0, var10.length);
      }

      this.mac.doFinal(var12, 0);
      if (!Arrays.areEqual(var11, var12)) {
         throw new InvalidCipherTextException("Invalid MAC.");
      } else {
         byte[] var13 = new byte[var8];
         System.arraycopy(var14, 0, var13, 0, var8);
         return var13;
      }
   }

   public byte[] processBlock(byte[] var1, int var2, int var3) throws InvalidCipherTextException {
      if (this.forEncryption) {
         if (this.keyPairGenerator != null) {
            EphemeralKeyPair var4 = this.keyPairGenerator.generate();
            this.privParam = var4.getKeyPair().getPrivate();
            this.V = var4.getEncodedPublicKey();
         }
      } else if (this.keyParser != null) {
         ByteArrayInputStream var9 = new ByteArrayInputStream(var1, var2, var3);

         try {
            this.pubParam = this.keyParser.readKey(var9);
         } catch (IOException var8) {
            throw new InvalidCipherTextException("unable to recover ephemeral public key: " + var8.getMessage(), var8);
         }

         int var5 = var3 - var9.available();
         this.V = new byte[var5];
         System.arraycopy(var1, var2, this.V, 0, this.V.length);
      }

      this.agree.init(this.privParam);
      BigInteger var10 = this.agree.calculateAgreement(this.pubParam);
      byte[] var11 = BigIntegers.asUnsignedByteArray(this.agree.getFieldSize(), var10);
      Object var6 = null;
      byte[] var12;
      if (this.V.length != 0) {
         var12 = new byte[this.V.length + var11.length];
         System.arraycopy(this.V, 0, var12, 0, this.V.length);
         System.arraycopy(var11, 0, var12, this.V.length, var11.length);
      } else {
         var12 = var11;
      }

      KDFParameters var7 = new KDFParameters(var12, this.param.getDerivationV());
      this.kdf.init(var7);
      return this.forEncryption ? this.encryptBlock(var1, var2, var3) : this.decryptBlock(var1, var2, var3);
   }
}
