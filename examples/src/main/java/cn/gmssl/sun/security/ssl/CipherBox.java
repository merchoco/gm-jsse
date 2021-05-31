package cn.gmssl.sun.security.ssl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Hashtable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import sun.misc.HexDumpEncoder;

final class CipherBox {
   static final CipherBox NULL = new CipherBox();
   private static final Debug debug = Debug.getInstance("ssl");
   private final ProtocolVersion protocolVersion;
   private final Cipher cipher;
   private int blockSize;
   private SecureRandom random;
   private static Hashtable<Integer, IvParameterSpec> masks;

   private CipherBox() {
      this.protocolVersion = ProtocolVersion.DEFAULT;
      this.cipher = null;
   }

   private CipherBox(ProtocolVersion var1, CipherSuite.BulkCipher var2, SecretKey var3, IvParameterSpec var4, SecureRandom var5, boolean var6) throws NoSuchAlgorithmException {
      try {
         this.protocolVersion = var1;
         this.cipher = JsseJce.getCipher(var2.transformation);
         int var7 = var6 ? 1 : 2;
         if (var5 == null) {
            var5 = JsseJce.getSecureRandom();
         }

         this.random = var5;
         if (var4 == null && var2.ivSize != 0 && var7 == 2 && var1.v >= ProtocolVersion.TLS11.v) {
            var4 = getFixedMask(var2.ivSize);
         }

         this.cipher.init(var7, var3, var4, var5);
         this.blockSize = this.cipher.getBlockSize();
         if (this.blockSize == 1) {
            this.blockSize = 0;
         }

      } catch (NoSuchAlgorithmException var8) {
         throw var8;
      } catch (Exception var9) {
         throw new NoSuchAlgorithmException("Could not create cipher " + var2, var9);
      } catch (ExceptionInInitializerError var10) {
         throw new NoSuchAlgorithmException("Could not create cipher " + var2, var10);
      }
   }

   static CipherBox newCipherBox(ProtocolVersion var0, CipherSuite.BulkCipher var1, SecretKey var2, IvParameterSpec var3, SecureRandom var4, boolean var5) throws NoSuchAlgorithmException {
      if (!var1.allowed) {
         throw new NoSuchAlgorithmException("Unsupported cipher " + var1);
      } else {
         return var1 == CipherSuite.B_NULL ? NULL : new CipherBox(var0, var1, var2, var3, var4, var5);
      }
   }

   private static IvParameterSpec getFixedMask(int var0) {
      if (masks == null) {
         masks = new Hashtable(5);
      }

      IvParameterSpec var1 = (IvParameterSpec)masks.get(var0);
      if (var1 == null) {
         var1 = new IvParameterSpec(new byte[var0]);
         masks.put(var0, var1);
      }

      return var1;
   }

   int encrypt(byte[] var1, int var2, int var3) {
      if (this.cipher == null) {
         return var3;
      } else {
         try {
            if (this.blockSize != 0) {
               if (this.protocolVersion.v >= ProtocolVersion.TLS11.v) {
                  byte[] var4 = new byte[this.blockSize];
                  this.random.nextBytes(var4);
                  System.arraycopy(var1, var2, var1, var2 + var4.length, var3);
                  System.arraycopy(var4, 0, var1, var2, var4.length);
                  var3 += var4.length;
               }

               var3 = addPadding(var1, var2, var3, this.blockSize);
            }

            if (debug != null && Debug.isOn("plaintext")) {
               try {
                  HexDumpEncoder var7 = new HexDumpEncoder();
                  System.out.println("Padded plaintext before ENCRYPTION:  len = " + var3);
                  var7.encodeBuffer(new ByteArrayInputStream(var1, var2, var3), System.out);
               } catch (IOException var5) {
                  ;
               }
            }

            int var8 = this.cipher.update(var1, var2, var3, var1, var2);
            if (var8 != var3) {
               throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName());
            } else {
               return var8;
            }
         } catch (ShortBufferException var6) {
            throw new ArrayIndexOutOfBoundsException(var6.toString());
         }
      }
   }

   int encrypt(ByteBuffer var1) {
      int var2 = var1.remaining();
      if (this.cipher == null) {
         var1.position(var1.limit());
         return var2;
      } else {
         try {
            int var3 = var1.position();
            if (this.blockSize != 0) {
               if (this.protocolVersion.v >= ProtocolVersion.TLS11.v) {
                  byte[] var9 = new byte[this.blockSize];
                  this.random.nextBytes(var9);
                  Object var5 = null;
                  int var6 = var1.limit();
                  byte[] var12;
                  if (var1.hasArray()) {
                     var12 = var1.array();
                     System.arraycopy(var12, var3, var12, var3 + var9.length, var6 - var3);
                     var1.limit(var6 + var9.length);
                  } else {
                     var12 = new byte[var6 - var3];
                     var1.get(var12, 0, var6 - var3);
                     var1.position(var3 + var9.length);
                     var1.limit(var6 + var9.length);
                     var1.put(var12);
                  }

                  var1.position(var3);
                  var1.put(var9);
                  var1.position(var3);
               }

               var2 = addPadding(var1, this.blockSize);
               var1.position(var3);
            }

            if (debug != null && Debug.isOn("plaintext")) {
               try {
                  HexDumpEncoder var10 = new HexDumpEncoder();
                  System.out.println("Padded plaintext before ENCRYPTION:  len = " + var2);
                  var10.encodeBuffer(var1, System.out);
               } catch (IOException var7) {
                  ;
               }

               var1.position(var3);
            }

            ByteBuffer var11 = var1.duplicate();
            int var13 = this.cipher.update(var11, var1);
            if (var1.position() != var11.position()) {
               throw new RuntimeException("bytebuffer padding error");
            } else if (var13 != var2) {
               throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName());
            } else {
               return var13;
            }
         } catch (ShortBufferException var8) {
            RuntimeException var4 = new RuntimeException(var8.toString());
            var4.initCause(var8);
            throw var4;
         }
      }
   }

   int decrypt(byte[] var1, int var2, int var3) throws BadPaddingException {
      if (this.cipher == null) {
         return var3;
      } else {
         try {
            int var4 = this.cipher.update(var1, var2, var3, var1, var2);
            if (var4 != var3) {
               throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName());
            } else {
               if (debug != null && Debug.isOn("plaintext")) {
                  try {
                     HexDumpEncoder var5 = new HexDumpEncoder();
                     System.out.println("Padded plaintext after DECRYPTION:  len = " + var4);
                     var5.encodeBuffer(new ByteArrayInputStream(var1, var2, var4), System.out);
                  } catch (IOException var6) {
                     ;
                  }
               }

               if (this.blockSize != 0) {
                  var4 = removePadding(var1, var2, var4, this.blockSize, this.protocolVersion);
                  if (this.protocolVersion.v >= ProtocolVersion.TLS11.v) {
                     if (var4 < this.blockSize) {
                        throw new BadPaddingException("invalid explicit IV");
                     }

                     System.arraycopy(var1, var2 + this.blockSize, var1, var2, var4 - this.blockSize);
                     var4 -= this.blockSize;
                  }
               }

               return var4;
            }
         } catch (ShortBufferException var7) {
            throw new ArrayIndexOutOfBoundsException(var7.toString());
         }
      }
   }

   int decrypt(ByteBuffer var1) throws BadPaddingException {
      int var2 = var1.remaining();
      if (this.cipher == null) {
         var1.position(var1.limit());
         return var2;
      } else {
         try {
            int var3 = var1.position();
            ByteBuffer var10 = var1.duplicate();
            int var5 = this.cipher.update(var10, var1);
            if (var5 != var2) {
               throw new RuntimeException("Cipher buffering error in JCE provider " + this.cipher.getProvider().getName());
            } else {
               HexDumpEncoder var6;
               if (debug != null && Debug.isOn("plaintext")) {
                  var1.position(var3);

                  try {
                     var6 = new HexDumpEncoder();
                     System.out.println("Padded plaintext after DECRYPTION:  len = " + var5);
                     var6.encodeBuffer(var1, System.out);
                  } catch (IOException var8) {
                     ;
                  }
               }

               if (this.blockSize != 0) {
                  var1.position(var3);
                  var5 = removePadding(var1, this.blockSize, this.protocolVersion);
                  if (this.protocolVersion.v >= ProtocolVersion.TLS11.v) {
                     if (var5 < this.blockSize) {
                        throw new BadPaddingException("invalid explicit IV");
                     }

                     var6 = null;
                     int var7 = var1.limit();
                     byte[] var11;
                     if (var1.hasArray()) {
                        var11 = var1.array();
                        System.arraycopy(var11, var3 + var1.arrayOffset() + this.blockSize, var11, var3 + var1.arrayOffset(), var7 - var3 - this.blockSize);
                        var1.limit(var7 - this.blockSize);
                     } else {
                        var11 = new byte[var7 - var3 - this.blockSize];
                        var1.position(var3 + this.blockSize);
                        var1.get(var11);
                        var1.position(var3);
                        var1.put(var11);
                        var1.limit(var7 - this.blockSize);
                     }

                     var7 = var1.limit();
                     var1.position(var7);
                  }
               }

               return var5;
            }
         } catch (ShortBufferException var9) {
            RuntimeException var4 = new RuntimeException(var9.toString());
            var4.initCause(var9);
            throw var4;
         }
      }
   }

   private static int addPadding(byte[] var0, int var1, int var2, int var3) {
      int var4 = var2 + 1;
      if (var4 % var3 != 0) {
         var4 += var3 - 1;
         var4 -= var4 % var3;
      }

      byte var5 = (byte)(var4 - var2);
      if (var0.length < var4 + var1) {
         throw new IllegalArgumentException("no space to pad buffer");
      } else {
         int var6 = 0;

         for(var1 += var2; var6 < var5; ++var6) {
            var0[var1++] = (byte)(var5 - 1);
         }

         return var4;
      }
   }

   private static int addPadding(ByteBuffer var0, int var1) {
      int var2 = var0.remaining();
      int var3 = var0.position();
      int var4 = var2 + 1;
      if (var4 % var1 != 0) {
         var4 += var1 - 1;
         var4 -= var4 % var1;
      }

      byte var5 = (byte)(var4 - var2);
      var0.limit(var4 + var3);
      int var6 = 0;

      for(var3 += var2; var6 < var5; ++var6) {
         var0.put(var3++, (byte)(var5 - 1));
      }

      var0.position(var3);
      var0.limit(var3);
      return var4;
   }

   private static int removePadding(byte[] var0, int var1, int var2, int var3, ProtocolVersion var4) throws BadPaddingException {
      int var5 = var1 + var2 - 1;
      int var6 = var0[var5] & 255;
      int var7 = var2 - (var6 + 1);
      if (var7 < 0) {
         throw new BadPaddingException("Padding length invalid: " + var6);
      } else {
         if (var4.v >= ProtocolVersion.TLS10.v) {
            for(int var8 = 1; var8 <= var6; ++var8) {
               int var9 = var0[var5 - var8] & 255;
               if (var9 != var6) {
                  throw new BadPaddingException("Invalid TLS padding: " + var9);
               }
            }
         } else if (var6 > var3) {
            throw new BadPaddingException("Invalid SSLv3 padding: " + var6);
         }

         return var7;
      }
   }

   private static int removePadding(ByteBuffer var0, int var1, ProtocolVersion var2) throws BadPaddingException {
      int var3 = var0.remaining();
      int var4 = var0.position();
      int var5 = var4 + var3 - 1;
      int var6 = var0.get(var5) & 255;
      int var7 = var3 - (var6 + 1);
      if (var7 < 0) {
         throw new BadPaddingException("Padding length invalid: " + var6);
      } else {
         if (var2.v >= ProtocolVersion.TLS10.v) {
            var0.put(var5, (byte)0);

            for(int var8 = 1; var8 <= var6; ++var8) {
               int var9 = var0.get(var5 - var8) & 255;
               if (var9 != var6) {
                  throw new BadPaddingException("Invalid TLS padding: " + var9);
               }
            }
         } else if (var6 > var1) {
            throw new BadPaddingException("Invalid SSLv3 padding: " + var6);
         }

         var0.position(var4 + var7);
         var0.limit(var4 + var7);
         return var7;
      }
   }

   void dispose() {
      try {
         if (this.cipher != null) {
            this.cipher.doFinal();
         }
      } catch (GeneralSecurityException var2) {
         ;
      }

   }
}
