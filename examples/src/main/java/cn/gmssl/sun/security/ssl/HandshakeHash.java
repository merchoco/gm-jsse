package cn.gmssl.sun.security.ssl;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.Set;

final class HandshakeHash {
   private int version = -1;
   private ByteArrayOutputStream data = new ByteArrayOutputStream();
   private final boolean isServer;
   private MessageDigest md5;
   private MessageDigest sha;
   private final int clonesNeeded;
   private MessageDigest sm3;
   private boolean cvAlgDetermined = false;
   private String cvAlg;
   private MessageDigest finMD;

   HandshakeHash(boolean var1, boolean var2, Set<String> var3) {
      this.isServer = var1;
      this.clonesNeeded = var2 ? 3 : 2;
   }

   void update(byte[] var1, int var2, int var3) {
      switch(this.version) {
      case 1:
         this.md5.update(var1, var2, var3);
         this.sha.update(var1, var2, var3);
         break;
      case 2:
      default:
         if (this.finMD != null) {
            this.finMD.update(var1, var2, var3);
         }

         this.data.write(var1, var2, var3);
         break;
      case 3:
         this.sha.update(var1, var2, var3);
         this.sm3.update(var1, var2, var3);
         break;
      case 4:
         this.sm3.update(var1, var2, var3);
      }

   }

   void reset() {
      if (this.version != -1) {
         throw new RuntimeException("reset() can be only be called before protocolDetermined");
      } else {
         this.data.reset();
      }
   }

   void protocolDetermined(ProtocolVersion var1) {
      if (this.version == -1) {
         this.version = var1.compareTo(ProtocolVersion.TLS12) >= 0 ? 2 : 1;
         if (var1.major == 1) {
            if (var1.minor == 0) {
               this.version = 3;
            } else {
               if (var1.minor != 1) {
                  throw new RuntimeException("unsupported protocol version " + var1.major + "." + var1.minor);
               }

               this.version = 4;
            }
         }

         Object var2 = null;
         byte[] var7;
         switch(this.version) {
         case 1:
            try {
               this.md5 = CloneableDigest.getDigest("MD5", this.clonesNeeded);
               this.sha = CloneableDigest.getDigest("SHA", this.clonesNeeded);
            } catch (NoSuchAlgorithmException var6) {
               throw new RuntimeException("Algorithm MD5 or SHA not available", var6);
            }

            var7 = this.data.toByteArray();
            this.update(var7, 0, var7.length);
         case 2:
         default:
            break;
         case 3:
            try {
               this.sha = CloneableDigest.getDigest("SHA", this.clonesNeeded);
               this.sm3 = CloneableDigest.getDigest("SM3", this.clonesNeeded);
            } catch (NoSuchAlgorithmException var5) {
               throw new RuntimeException("Algorithm SHA or SM3 not available", var5);
            }

            var7 = this.data.toByteArray();
            this.update(var7, 0, var7.length);
            break;
         case 4:
            try {
               this.sm3 = CloneableDigest.getDigest("SM3", this.clonesNeeded);
            } catch (NoSuchAlgorithmException var4) {
               throw new RuntimeException("Algorithm SM3 not available", var4);
            }

            var7 = this.data.toByteArray();
            this.update(var7, 0, var7.length);
         }

      }
   }

   MessageDigest getMD5Clone() {
      if (this.version != 1) {
         throw new RuntimeException("getMD5Clone() can be only be called for TLS 1.1");
      } else {
         return cloneDigest(this.md5);
      }
   }

   MessageDigest getSHAClone() {
      if (this.version != 1 && this.version != 3) {
         throw new RuntimeException("getSHAClone() can be only be called for TLS 1.1 or GB");
      } else {
         return cloneDigest(this.sha);
      }
   }

   MessageDigest getSM3Clone() {
      if (this.version != 3 && this.version != 4) {
         throw new RuntimeException("getSM3Clone() can be only be called for GB");
      } else {
         return cloneDigest(this.sm3);
      }
   }

   private static MessageDigest cloneDigest(MessageDigest var0) {
      try {
         return (MessageDigest)var0.clone();
      } catch (CloneNotSupportedException var2) {
         throw new RuntimeException("Could not clone digest", var2);
      }
   }

   private static String normalizeAlgName(String var0) {
      var0 = var0.toUpperCase(Locale.US);
      if (var0.startsWith("SHA")) {
         if (var0.length() == 3) {
            return "SHA-1";
         }

         if (var0.charAt(3) != '-') {
            return "SHA-" + var0.substring(3);
         }
      }

      return var0;
   }

   void setFinishedAlg(String var1) {
      if (var1 == null) {
         throw new RuntimeException("setFinishedAlg's argument cannot be null");
      } else if (this.finMD == null) {
         try {
            this.finMD = CloneableDigest.getDigest(normalizeAlgName(var1), 2);
         } catch (NoSuchAlgorithmException var3) {
            return;
         }

         this.finMD.update(this.data.toByteArray());
      }
   }

   void restrictCertificateVerifyAlgs(Set<String> var1) {
      if (this.version == 1) {
         throw new RuntimeException("setCertificateVerifyAlg() cannot be called for TLS 1.1");
      }
   }

   void setCertificateVerifyAlg(String var1) {
      if (!this.cvAlgDetermined) {
         this.cvAlg = var1 == null ? null : normalizeAlgName(var1);
         this.cvAlgDetermined = true;
      }
   }

   byte[] getAllHandshakeMessages() {
      return this.data.toByteArray();
   }

   byte[] getFinishedHash() {
      try {
         return cloneDigest(this.finMD).digest();
      } catch (Exception var2) {
         throw new Error("BAD");
      }
   }
}
