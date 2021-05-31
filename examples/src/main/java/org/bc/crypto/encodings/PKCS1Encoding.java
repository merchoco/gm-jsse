package org.bc.crypto.encodings;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import org.bc.crypto.AsymmetricBlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.InvalidCipherTextException;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ParametersWithRandom;

public class PKCS1Encoding implements AsymmetricBlockCipher {
   public static final String STRICT_LENGTH_ENABLED_PROPERTY = "org.bc.pkcs1.strict";
   private static final int HEADER_LENGTH = 10;
   private SecureRandom random;
   private AsymmetricBlockCipher engine;
   private boolean forEncryption;
   private boolean forPrivateKey;
   private boolean useStrictLength;

   public PKCS1Encoding(AsymmetricBlockCipher var1) {
      this.engine = var1;
      this.useStrictLength = this.useStrict();
   }

   private boolean useStrict() {
      String var1 = (String)AccessController.doPrivileged(new PrivilegedAction() {
         public Object run() {
            return System.getProperty("org.bc.pkcs1.strict");
         }
      });
      return var1 == null || var1.equals("true");
   }

   public AsymmetricBlockCipher getUnderlyingCipher() {
      return this.engine;
   }

   public void init(boolean var1, CipherParameters var2) {
      AsymmetricKeyParameter var3;
      if (var2 instanceof ParametersWithRandom) {
         ParametersWithRandom var4 = (ParametersWithRandom)var2;
         this.random = var4.getRandom();
         var3 = (AsymmetricKeyParameter)var4.getParameters();
      } else {
         this.random = new SecureRandom();
         var3 = (AsymmetricKeyParameter)var2;
      }

      this.engine.init(var1, var2);
      this.forPrivateKey = var3.isPrivate();
      this.forEncryption = var1;
   }

   public int getInputBlockSize() {
      int var1 = this.engine.getInputBlockSize();
      return this.forEncryption ? var1 - 10 : var1;
   }

   public int getOutputBlockSize() {
      int var1 = this.engine.getOutputBlockSize();
      return this.forEncryption ? var1 : var1 - 10;
   }

   public byte[] processBlock(byte[] var1, int var2, int var3) throws InvalidCipherTextException {
      return this.forEncryption ? this.encodeBlock(var1, var2, var3) : this.decodeBlock(var1, var2, var3);
   }

   private byte[] encodeBlock(byte[] var1, int var2, int var3) throws InvalidCipherTextException {
      if (var3 > this.getInputBlockSize()) {
         throw new IllegalArgumentException("input data too large");
      } else {
         byte[] var4 = new byte[this.engine.getInputBlockSize()];
         int var5;
         if (this.forPrivateKey) {
            var4[0] = 1;

            for(var5 = 1; var5 != var4.length - var3 - 1; ++var5) {
               var4[var5] = -1;
            }
         } else {
            this.random.nextBytes(var4);
            var4[0] = 2;

            for(var5 = 1; var5 != var4.length - var3 - 1; ++var5) {
               while(var4[var5] == 0) {
                  var4[var5] = (byte)this.random.nextInt();
               }
            }
         }

         var4[var4.length - var3 - 1] = 0;
         System.arraycopy(var1, var2, var4, var4.length - var3, var3);
         return this.engine.processBlock(var4, 0, var4.length);
      }
   }

   private byte[] decodeBlock(byte[] var1, int var2, int var3) throws InvalidCipherTextException {
      byte[] var4 = this.engine.processBlock(var1, var2, var3);
      if (var4.length < this.getOutputBlockSize()) {
         throw new InvalidCipherTextException("block truncated");
      } else {
         byte var5 = var4[0];
         if (this.forPrivateKey) {
            if (var5 != 2) {
               throw new InvalidCipherTextException("unknown block type");
            }
         } else if (var5 != 1) {
            throw new InvalidCipherTextException("unknown block type");
         }

         if (this.useStrictLength && var4.length != this.engine.getOutputBlockSize()) {
            throw new InvalidCipherTextException("block incorrect size");
         } else {
            int var6;
            for(var6 = 1; var6 != var4.length; ++var6) {
               byte var7 = var4[var6];
               if (var7 == 0) {
                  break;
               }

               if (var5 == 1 && var7 != -1) {
                  throw new InvalidCipherTextException("block padding incorrect");
               }
            }

            ++var6;
            if (var6 <= var4.length && var6 >= 10) {
               byte[] var8 = new byte[var4.length - var6];
               System.arraycopy(var4, var6, var8, 0, var8.length);
               return var8;
            } else {
               throw new InvalidCipherTextException("no data in block");
            }
         }
      }
   }
}
