package org.bc.crypto.signers;

import java.util.Hashtable;
import org.bc.crypto.AsymmetricBlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.CryptoException;
import org.bc.crypto.Digest;
import org.bc.crypto.InvalidCipherTextException;
import org.bc.crypto.SignerWithRecovery;
import org.bc.crypto.params.RSAKeyParameters;
import org.bc.util.Arrays;
import org.bc.util.Integers;

public class ISO9796d2Signer implements SignerWithRecovery {
   public static final int TRAILER_IMPLICIT = 188;
   public static final int TRAILER_RIPEMD160 = 12748;
   public static final int TRAILER_RIPEMD128 = 13004;
   public static final int TRAILER_SHA1 = 13260;
   public static final int TRAILER_SHA256 = 13516;
   public static final int TRAILER_SHA512 = 13772;
   public static final int TRAILER_SHA384 = 14028;
   public static final int TRAILER_WHIRLPOOL = 14284;
   private static Hashtable trailerMap = new Hashtable();
   private Digest digest;
   private AsymmetricBlockCipher cipher;
   private int trailer;
   private int keyBits;
   private byte[] block;
   private byte[] mBuf;
   private int messageLength;
   private boolean fullMessage;
   private byte[] recoveredMessage;
   private byte[] preSig;
   private byte[] preBlock;

   static {
      trailerMap.put("RIPEMD128", Integers.valueOf(13004));
      trailerMap.put("RIPEMD160", Integers.valueOf(12748));
      trailerMap.put("SHA-1", Integers.valueOf(13260));
      trailerMap.put("SHA-256", Integers.valueOf(13516));
      trailerMap.put("SHA-384", Integers.valueOf(14028));
      trailerMap.put("SHA-512", Integers.valueOf(13772));
      trailerMap.put("Whirlpool", Integers.valueOf(14284));
   }

   public ISO9796d2Signer(AsymmetricBlockCipher var1, Digest var2, boolean var3) {
      this.cipher = var1;
      this.digest = var2;
      if (var3) {
         this.trailer = 188;
      } else {
         Integer var4 = (Integer)trailerMap.get(var2.getAlgorithmName());
         if (var4 == null) {
            throw new IllegalArgumentException("no valid trailer for digest");
         }

         this.trailer = var4;
      }

   }

   public ISO9796d2Signer(AsymmetricBlockCipher var1, Digest var2) {
      this(var1, var2, false);
   }

   public void init(boolean var1, CipherParameters var2) {
      RSAKeyParameters var3 = (RSAKeyParameters)var2;
      this.cipher.init(var1, var3);
      this.keyBits = var3.getModulus().bitLength();
      this.block = new byte[(this.keyBits + 7) / 8];
      if (this.trailer == 188) {
         this.mBuf = new byte[this.block.length - this.digest.getDigestSize() - 2];
      } else {
         this.mBuf = new byte[this.block.length - this.digest.getDigestSize() - 3];
      }

      this.reset();
   }

   private boolean isSameAs(byte[] var1, byte[] var2) {
      boolean var3 = true;
      int var4;
      if (this.messageLength > this.mBuf.length) {
         if (this.mBuf.length > var2.length) {
            var3 = false;
         }

         for(var4 = 0; var4 != this.mBuf.length; ++var4) {
            if (var1[var4] != var2[var4]) {
               var3 = false;
            }
         }
      } else {
         if (this.messageLength != var2.length) {
            var3 = false;
         }

         for(var4 = 0; var4 != var2.length; ++var4) {
            if (var1[var4] != var2[var4]) {
               var3 = false;
            }
         }
      }

      return var3;
   }

   private void clearBlock(byte[] var1) {
      for(int var2 = 0; var2 != var1.length; ++var2) {
         var1[var2] = 0;
      }

   }

   public void updateWithRecoveredMessage(byte[] var1) throws InvalidCipherTextException {
      byte[] var2 = this.cipher.processBlock(var1, 0, var1.length);
      if ((var2[0] & 192 ^ 64) != 0) {
         throw new InvalidCipherTextException("malformed signature");
      } else if ((var2[var2.length - 1] & 15 ^ 12) != 0) {
         throw new InvalidCipherTextException("malformed signature");
      } else {
         boolean var3 = false;
         int var4;
         byte var6;
         if ((var2[var2.length - 1] & 255 ^ 188) == 0) {
            var6 = 1;
         } else {
            var4 = (var2[var2.length - 2] & 255) << 8 | var2[var2.length - 1] & 255;
            Integer var5 = (Integer)trailerMap.get(this.digest.getAlgorithmName());
            if (var5 == null) {
               throw new IllegalArgumentException("unrecognised hash in signature");
            }

            if (var4 != var5) {
               throw new IllegalStateException("signer initialised with wrong digest for trailer " + var4);
            }

            var6 = 2;
         }

         boolean var7 = false;

         for(var4 = 0; var4 != var2.length && (var2[var4] & 15 ^ 10) != 0; ++var4) {
            ;
         }

         ++var4;
         int var8 = var2.length - var6 - this.digest.getDigestSize();
         if (var8 - var4 <= 0) {
            throw new InvalidCipherTextException("malformed block");
         } else {
            if ((var2[0] & 32) == 0) {
               this.fullMessage = true;
               this.recoveredMessage = new byte[var8 - var4];
               System.arraycopy(var2, var4, this.recoveredMessage, 0, this.recoveredMessage.length);
            } else {
               this.fullMessage = false;
               this.recoveredMessage = new byte[var8 - var4];
               System.arraycopy(var2, var4, this.recoveredMessage, 0, this.recoveredMessage.length);
            }

            this.preSig = var1;
            this.preBlock = var2;
            this.digest.update(this.recoveredMessage, 0, this.recoveredMessage.length);
            this.messageLength = this.recoveredMessage.length;
         }
      }
   }

   public void update(byte var1) {
      this.digest.update(var1);
      if (this.preSig == null && this.messageLength < this.mBuf.length) {
         this.mBuf[this.messageLength] = var1;
      }

      ++this.messageLength;
   }

   public void update(byte[] var1, int var2, int var3) {
      this.digest.update(var1, var2, var3);
      if (this.preSig == null && this.messageLength < this.mBuf.length) {
         for(int var4 = 0; var4 < var3 && var4 + this.messageLength < this.mBuf.length; ++var4) {
            this.mBuf[this.messageLength + var4] = var1[var2 + var4];
         }
      }

      this.messageLength += var3;
   }

   public void reset() {
      this.digest.reset();
      this.messageLength = 0;
      this.clearBlock(this.mBuf);
      if (this.recoveredMessage != null) {
         this.clearBlock(this.recoveredMessage);
      }

      this.recoveredMessage = null;
      this.fullMessage = false;
   }

   public byte[] generateSignature() throws CryptoException {
      int var1 = this.digest.getDigestSize();
      boolean var2 = false;
      boolean var3 = false;
      byte var7;
      int var8;
      if (this.trailer == 188) {
         var7 = 8;
         var8 = this.block.length - var1 - 1;
         this.digest.doFinal(this.block, var8);
         this.block[this.block.length - 1] = -68;
      } else {
         var7 = 16;
         var8 = this.block.length - var1 - 2;
         this.digest.doFinal(this.block, var8);
         this.block[this.block.length - 2] = (byte)(this.trailer >>> 8);
         this.block[this.block.length - 1] = (byte)this.trailer;
      }

      boolean var4 = false;
      int var5 = (var1 + this.messageLength) * 8 + var7 + 4 - this.keyBits;
      int var6;
      byte var9;
      if (var5 > 0) {
         var6 = this.messageLength - (var5 + 7) / 8;
         var9 = 96;
         var8 -= var6;
         System.arraycopy(this.mBuf, 0, this.block, var8, var6);
      } else {
         var9 = 64;
         var8 -= this.messageLength;
         System.arraycopy(this.mBuf, 0, this.block, var8, this.messageLength);
      }

      if (var8 - 1 > 0) {
         for(var6 = var8 - 1; var6 != 0; --var6) {
            this.block[var6] = -69;
         }

         this.block[var8 - 1] = (byte)(this.block[var8 - 1] ^ 1);
         this.block[0] = 11;
         this.block[0] |= var9;
      } else {
         this.block[0] = 10;
         this.block[0] |= var9;
      }

      byte[] var10 = this.cipher.processBlock(this.block, 0, this.block.length);
      this.clearBlock(this.mBuf);
      this.clearBlock(this.block);
      return var10;
   }

   public boolean verifySignature(byte[] var1) {
      Object var2 = null;
      boolean var3;
      byte[] var11;
      if (this.preSig == null) {
         var3 = false;

         try {
            var11 = this.cipher.processBlock(var1, 0, var1.length);
         } catch (Exception var10) {
            return false;
         }
      } else {
         if (!Arrays.areEqual(this.preSig, var1)) {
            throw new IllegalStateException("updateWithRecoveredMessage called on different signature");
         }

         var3 = true;
         var11 = this.preBlock;
         this.preSig = null;
         this.preBlock = null;
      }

      if ((var11[0] & 192 ^ 64) != 0) {
         return this.returnFalse(var11);
      } else if ((var11[var11.length - 1] & 15 ^ 12) != 0) {
         return this.returnFalse(var11);
      } else {
         boolean var4 = false;
         int var5;
         byte var12;
         if ((var11[var11.length - 1] & 255 ^ 188) == 0) {
            var12 = 1;
         } else {
            var5 = (var11[var11.length - 2] & 255) << 8 | var11[var11.length - 1] & 255;
            Integer var6 = (Integer)trailerMap.get(this.digest.getAlgorithmName());
            if (var6 == null) {
               throw new IllegalArgumentException("unrecognised hash in signature");
            }

            if (var5 != var6) {
               throw new IllegalStateException("signer initialised with wrong digest for trailer " + var5);
            }

            var12 = 2;
         }

         boolean var13 = false;

         for(var5 = 0; var5 != var11.length && (var11[var5] & 15 ^ 10) != 0; ++var5) {
            ;
         }

         ++var5;
         byte[] var14 = new byte[this.digest.getDigestSize()];
         int var7 = var11.length - var12 - var14.length;
         if (var7 - var5 <= 0) {
            return this.returnFalse(var11);
         } else {
            boolean var8;
            int var9;
            if ((var11[0] & 32) == 0) {
               this.fullMessage = true;
               if (this.messageLength > var7 - var5) {
                  return this.returnFalse(var11);
               }

               this.digest.reset();
               this.digest.update(var11, var5, var7 - var5);
               this.digest.doFinal(var14, 0);
               var8 = true;

               for(var9 = 0; var9 != var14.length; ++var9) {
                  var11[var7 + var9] ^= var14[var9];
                  if (var11[var7 + var9] != 0) {
                     var8 = false;
                  }
               }

               if (!var8) {
                  return this.returnFalse(var11);
               }

               this.recoveredMessage = new byte[var7 - var5];
               System.arraycopy(var11, var5, this.recoveredMessage, 0, this.recoveredMessage.length);
            } else {
               this.fullMessage = false;
               this.digest.doFinal(var14, 0);
               var8 = true;

               for(var9 = 0; var9 != var14.length; ++var9) {
                  var11[var7 + var9] ^= var14[var9];
                  if (var11[var7 + var9] != 0) {
                     var8 = false;
                  }
               }

               if (!var8) {
                  return this.returnFalse(var11);
               }

               this.recoveredMessage = new byte[var7 - var5];
               System.arraycopy(var11, var5, this.recoveredMessage, 0, this.recoveredMessage.length);
            }

            if (this.messageLength != 0 && !var3 && !this.isSameAs(this.mBuf, this.recoveredMessage)) {
               return this.returnFalse(var11);
            } else {
               this.clearBlock(this.mBuf);
               this.clearBlock(var11);
               return true;
            }
         }
      }
   }

   private boolean returnFalse(byte[] var1) {
      this.clearBlock(this.mBuf);
      this.clearBlock(var1);
      return false;
   }

   public boolean hasFullMessage() {
      return this.fullMessage;
   }

   public byte[] getRecoveredMessage() {
      return this.recoveredMessage;
   }
}
