package cn.gmssl.com.sun.crypto.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Locale;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;

final class CipherCore {
   private byte[] buffer = null;
   private int blockSize = 0;
   private int unitBytes = 0;
   private int buffered = 0;
   private int minBytes = 0;
   private int diffBlocksize = 0;
   private Padding padding = null;
   private FeedbackCipher cipher = null;
   private int cipherMode = 0;
   private boolean decrypting = false;
   private static final int ECB_MODE = 0;
   private static final int CBC_MODE = 1;
   private static final int CFB_MODE = 2;
   private static final int OFB_MODE = 3;
   private static final int PCBC_MODE = 4;
   private static final int CTR_MODE = 5;
   private static final int CTS_MODE = 6;

   CipherCore(SymmetricCipher var1, int var2) {
      this.blockSize = var2;
      this.unitBytes = var2;
      this.diffBlocksize = var2;
      this.buffer = new byte[this.blockSize * 2];
      this.cipher = new ElectronicCodeBook(var1);
      this.padding = new PKCS5Padding(this.blockSize);
   }

   void setMode(String var1) throws NoSuchAlgorithmException {
      if (var1 == null) {
         throw new NoSuchAlgorithmException("null mode");
      } else {
         String var2 = var1.toUpperCase(Locale.ENGLISH);
         if (!var2.equals("ECB")) {
            SymmetricCipher var3 = this.cipher.getEmbeddedCipher();
            if (var2.equals("CBC")) {
               this.cipherMode = 1;
               this.cipher = new CipherBlockChaining(var3);
            } else if (var2.equals("CTS")) {
               this.cipherMode = 6;
               this.cipher = new CipherTextStealing(var3);
               this.minBytes = this.blockSize + 1;
               this.padding = null;
            } else if (var2.equals("CTR")) {
               this.cipherMode = 5;
               this.cipher = new CounterMode(var3);
               this.unitBytes = 1;
               this.padding = null;
            } else if (var2.startsWith("CFB")) {
               this.cipherMode = 2;
               this.unitBytes = getNumOfUnit(var1, "CFB".length(), this.blockSize);
               this.cipher = new CipherFeedback(var3, this.unitBytes);
            } else if (var2.startsWith("OFB")) {
               this.cipherMode = 3;
               this.unitBytes = getNumOfUnit(var1, "OFB".length(), this.blockSize);
               this.cipher = new OutputFeedback(var3, this.unitBytes);
            } else {
               if (!var2.equals("PCBC")) {
                  throw new NoSuchAlgorithmException("Cipher mode: " + var1 + " not found");
               }

               this.cipherMode = 4;
               this.cipher = new PCBC(var3);
            }

         }
      }
   }

   private static int getNumOfUnit(String var0, int var1, int var2) throws NoSuchAlgorithmException {
      int var3 = var2;
      if (var0.length() > var1) {
         int var4;
         try {
            Integer var5 = Integer.valueOf(var0.substring(var1));
            var4 = var5;
            var3 = var4 >> 3;
         } catch (NumberFormatException var6) {
            throw new NoSuchAlgorithmException("Algorithm mode: " + var0 + " not implemented");
         }

         if (var4 % 8 != 0 || var3 > var2) {
            throw new NoSuchAlgorithmException("Invalid algorithm mode: " + var0);
         }
      }

      return var3;
   }

   void setPadding(String var1) throws NoSuchPaddingException {
      if (var1 == null) {
         throw new NoSuchPaddingException("null padding");
      } else {
         if (var1.equalsIgnoreCase("NoPadding")) {
            this.padding = null;
         } else if (var1.equalsIgnoreCase("ISO10126Padding")) {
            this.padding = new ISO10126Padding(this.blockSize);
         } else if (!var1.equalsIgnoreCase("PKCS5Padding")) {
            throw new NoSuchPaddingException("Padding: " + var1 + " not implemented");
         }

         if (this.padding != null && (this.cipherMode == 5 || this.cipherMode == 6)) {
            this.padding = null;
            throw new NoSuchPaddingException((this.cipherMode == 5 ? "CTR" : "CTS") + " mode must be used with NoPadding");
         }
      }
   }

   int getOutputSize(int var1) {
      int var2 = this.buffered + var1;
      if (this.padding == null) {
         return var2;
      } else if (this.decrypting) {
         return var2;
      } else if (this.unitBytes != this.blockSize) {
         return var2 < this.diffBlocksize ? this.diffBlocksize : var2 + this.blockSize - (var2 - this.diffBlocksize) % this.blockSize;
      } else {
         return var2 + this.padding.padLength(var2);
      }
   }

   byte[] getIV() {
      byte[] var1 = this.cipher.getIV();
      return var1 == null ? null : (byte[])var1.clone();
   }

   AlgorithmParameters getParameters(String var1) {
      AlgorithmParameters var2 = null;
      if (this.cipherMode == 0) {
         return null;
      } else {
         byte[] var3 = this.getIV();
         if (var3 != null) {
            Object var4;
            if (var1.equals("RC2")) {
               RC2Crypt var5 = (RC2Crypt)this.cipher.getEmbeddedCipher();
               var4 = new RC2ParameterSpec(var5.getEffectiveKeyBits(), var3);
            } else {
               var4 = new IvParameterSpec(var3);
            }

            try {
               var2 = AlgorithmParameters.getInstance(var1, "SunJCE");
            } catch (NoSuchAlgorithmException var7) {
               throw new RuntimeException("Cannot find " + var1 + " AlgorithmParameters implementation in SunJCE provider");
            } catch (NoSuchProviderException var8) {
               throw new RuntimeException("Cannot find SunJCE provider");
            }

            try {
               var2.init((AlgorithmParameterSpec)var4);
            } catch (InvalidParameterSpecException var6) {
               throw new RuntimeException("IvParameterSpec not supported");
            }
         }

         return var2;
      }
   }

   void init(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
      try {
         this.init(var1, var2, (AlgorithmParameterSpec)null, var3);
      } catch (InvalidAlgorithmParameterException var5) {
         throw new InvalidKeyException(var5.getMessage());
      }
   }

   void init(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      this.decrypting = var1 == 2 || var1 == 4;
      byte[] var5 = getKeyBytes(var2);
      byte[] var6;
      if (var3 == null) {
         var6 = null;
      } else if (var3 instanceof IvParameterSpec) {
         var6 = ((IvParameterSpec)var3).getIV();
         if (var6 == null || var6.length != this.blockSize) {
            throw new InvalidAlgorithmParameterException("Wrong IV length: must be " + this.blockSize + " bytes long");
         }
      } else {
         if (!(var3 instanceof RC2ParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Wrong parameter type: IV expected");
         }

         var6 = ((RC2ParameterSpec)var3).getIV();
         if (var6 != null && var6.length != this.blockSize) {
            throw new InvalidAlgorithmParameterException("Wrong IV length: must be " + this.blockSize + " bytes long");
         }
      }

      if (this.cipherMode == 0) {
         if (var6 != null) {
            throw new InvalidAlgorithmParameterException("ECB mode cannot use IV");
         }
      } else if (var6 == null) {
         if (this.decrypting) {
            throw new InvalidAlgorithmParameterException("Parameters missing");
         }

         if (var4 == null) {
            var4 = SunJCE.RANDOM;
         }

         var6 = new byte[this.blockSize];
         var4.nextBytes(var6);
      }

      this.buffered = 0;
      this.diffBlocksize = this.blockSize;
      String var7 = var2.getAlgorithm();
      this.cipher.init(this.decrypting, var7, var5, var6);
   }

   void init(int var1, Key var2, AlgorithmParameters var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      IvParameterSpec var5 = null;
      if (var3 != null) {
         try {
            var5 = (IvParameterSpec)var3.getParameterSpec(IvParameterSpec.class);
         } catch (InvalidParameterSpecException var7) {
            throw new InvalidAlgorithmParameterException("Wrong parameter type: IV expected");
         }
      }

      this.init(var1, var2, (AlgorithmParameterSpec)var5, var4);
   }

   static byte[] getKeyBytes(Key var0) throws InvalidKeyException {
      if (var0 == null) {
         throw new InvalidKeyException("No key given");
      } else if (!"RAW".equalsIgnoreCase(var0.getFormat())) {
         throw new InvalidKeyException("Wrong format: RAW bytes needed");
      } else {
         byte[] var1 = var0.getEncoded();
         if (var1 == null) {
            throw new InvalidKeyException("RAW key bytes missing");
         } else {
            return var1;
         }
      }
   }

   byte[] update(byte[] var1, int var2, int var3) {
      Object var4 = null;
      byte[] var5 = null;

      try {
         byte[] var8 = new byte[this.getOutputSize(var3)];
         int var6 = this.update(var1, var2, var3, var8, 0);
         if (var6 == var8.length) {
            var5 = var8;
         } else {
            var5 = new byte[var6];
            System.arraycopy(var8, 0, var5, 0, var6);
         }
      } catch (ShortBufferException var7) {
         ;
      }

      return var5;
   }

   int update(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException {
      int var6 = this.buffered + var3 - this.minBytes;
      if (this.padding != null && this.decrypting) {
         var6 -= this.blockSize;
      }

      var6 = var6 > 0 ? var6 - var6 % this.unitBytes : 0;
      if (var4 != null && var4.length - var5 >= var6) {
         if (var6 != 0) {
            byte[] var7 = new byte[var6];
            int var8 = var6 - this.buffered;
            int var9 = this.buffered;
            if (var8 < 0) {
               var8 = 0;
               var9 = var6;
            }

            if (this.buffered != 0) {
               System.arraycopy(this.buffer, 0, var7, 0, var9);
            }

            if (var8 > 0) {
               System.arraycopy(var1, var2, var7, var9, var8);
            }

            if (this.decrypting) {
               this.cipher.decrypt(var7, 0, var6, var4, var5);
            } else {
               this.cipher.encrypt(var7, 0, var6, var4, var5);
            }

            if (this.unitBytes != this.blockSize) {
               if (var6 < this.diffBlocksize) {
                  this.diffBlocksize -= var6;
               } else {
                  this.diffBlocksize = this.blockSize - (var6 - this.diffBlocksize) % this.blockSize;
               }
            }

            var3 -= var8;
            var2 += var8;
            int var10000 = var5 + var6;
            this.buffered -= var9;
            if (this.buffered > 0) {
               System.arraycopy(this.buffer, var9, this.buffer, 0, this.buffered);
            }
         }

         if (var3 > 0) {
            System.arraycopy(var1, var2, this.buffer, this.buffered, var3);
         }

         this.buffered += var3;
         return var6;
      } else {
         throw new ShortBufferException("Output buffer must be (at least) " + var6 + " bytes long");
      }
   }

   byte[] doFinal(byte[] var1, int var2, int var3) throws IllegalBlockSizeException, BadPaddingException {
      Object var4 = null;
      byte[] var5 = null;

      try {
         byte[] var8 = new byte[this.getOutputSize(var3)];
         int var6 = this.doFinal(var1, var2, var3, var8, 0);
         if (var6 < var8.length) {
            var5 = new byte[var6];
            if (var6 != 0) {
               System.arraycopy(var8, 0, var5, 0, var6);
            }
         } else {
            var5 = var8;
         }
      } catch (ShortBufferException var7) {
         ;
      }

      return var5;
   }

   int doFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws IllegalBlockSizeException, ShortBufferException, BadPaddingException {
      int var6 = this.buffered + var3;
      int var7 = var6;
      int var8 = 0;
      if (this.unitBytes != this.blockSize) {
         if (var6 < this.diffBlocksize) {
            var8 = this.diffBlocksize - var6;
         } else {
            var8 = this.blockSize - (var6 - this.diffBlocksize) % this.blockSize;
         }
      } else if (this.padding != null) {
         var8 = this.padding.padLength(var6);
      }

      if (var8 > 0 && var8 != this.blockSize && this.padding != null && this.decrypting) {
         throw new IllegalBlockSizeException("Input length must be multiple of " + this.blockSize + " when decrypting with padded cipher");
      } else {
         if (!this.decrypting && this.padding != null) {
            var7 = var6 + var8;
         }

         if (var4 == null) {
            throw new ShortBufferException("Output buffer is null");
         } else {
            int var9 = var4.length - var5;
            if ((this.decrypting && this.padding != null || var9 >= var7) && (!this.decrypting || var9 >= var7 - this.blockSize)) {
               byte[] var10 = var1;
               int var11 = var2;
               if (this.buffered != 0 || !this.decrypting && this.padding != null) {
                  var11 = 0;
                  var10 = new byte[var7];
                  if (this.buffered != 0) {
                     System.arraycopy(this.buffer, 0, var10, 0, this.buffered);
                  }

                  if (var3 != 0) {
                     System.arraycopy(var1, var2, var10, this.buffered, var3);
                  }

                  if (!this.decrypting && this.padding != null) {
                     this.padding.padWithLen(var10, var6, var8);
                  }
               }

               if (this.decrypting) {
                  if (var9 < var7) {
                     this.cipher.save();
                  }

                  byte[] var12 = new byte[var6];
                  var6 = this.finalNoPadding(var10, var11, var12, 0, var6);
                  int var13;
                  if (this.padding != null) {
                     var13 = this.padding.unpad(var12, 0, var6);
                     if (var13 < 0) {
                        throw new BadPaddingException("Given final block not properly padded");
                     }

                     var6 = var13;
                  }

                  if (var4.length - var5 < var6) {
                     this.cipher.restore();
                     throw new ShortBufferException("Output buffer too short: " + (var4.length - var5) + " bytes given, " + var6 + " bytes needed");
                  }

                  for(var13 = 0; var13 < var6; ++var13) {
                     var4[var5 + var13] = var12[var13];
                  }
               } else {
                  var6 = this.finalNoPadding(var10, var11, var4, var5, var7);
               }

               this.buffered = 0;
               this.diffBlocksize = this.blockSize;
               if (this.cipherMode != 0) {
                  this.cipher.reset();
               }

               return var6;
            } else {
               throw new ShortBufferException("Output buffer too short: " + var9 + " bytes given, " + var7 + " bytes needed");
            }
         }
      }
   }

   private int finalNoPadding(byte[] var1, int var2, byte[] var3, int var4, int var5) throws IllegalBlockSizeException {
      if (var1 != null && var5 != 0) {
         if (this.cipherMode != 2 && this.cipherMode != 3 && var5 % this.unitBytes != 0 && this.cipherMode != 6) {
            if (this.padding != null) {
               throw new IllegalBlockSizeException("Input length (with padding) not multiple of " + this.unitBytes + " bytes");
            } else {
               throw new IllegalBlockSizeException("Input length not multiple of " + this.unitBytes + " bytes");
            }
         } else {
            if (this.decrypting) {
               this.cipher.decryptFinal(var1, var2, var5, var3, var4);
            } else {
               this.cipher.encryptFinal(var1, var2, var5, var3, var4);
            }

            return var5;
         }
      } else {
         return 0;
      }
   }

   byte[] wrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
      byte[] var2 = null;

      try {
         byte[] var3 = var1.getEncoded();
         if (var3 == null || var3.length == 0) {
            throw new InvalidKeyException("Cannot get an encoding of the key to be wrapped");
         }

         var2 = this.doFinal(var3, 0, var3.length);
      } catch (BadPaddingException var4) {
         ;
      }

      return var2;
   }

   Key unwrap(byte[] var1, String var2, int var3) throws InvalidKeyException, NoSuchAlgorithmException {
      byte[] var4;
      try {
         var4 = this.doFinal(var1, 0, var1.length);
      } catch (BadPaddingException var6) {
         throw new InvalidKeyException("The wrapped key is not padded correctly");
      } catch (IllegalBlockSizeException var7) {
         throw new InvalidKeyException("The wrapped key does not have the correct length");
      }

      return ConstructKeys.constructKey(var4, var2, var3);
   }
}
