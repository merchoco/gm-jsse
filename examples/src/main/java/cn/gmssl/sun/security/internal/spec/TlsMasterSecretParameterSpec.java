package cn.gmssl.sun.security.internal.spec;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;

/** @deprecated */
@Deprecated
public class TlsMasterSecretParameterSpec implements AlgorithmParameterSpec {
   private final SecretKey premasterSecret;
   private final int majorVersion;
   private final int minorVersion;
   private final byte[] clientRandom;
   private final byte[] serverRandom;
   private final String prfHashAlg;
   private final int prfHashLength;
   private final int prfBlockSize;

   public TlsMasterSecretParameterSpec(SecretKey var1, int var2, int var3, byte[] var4, byte[] var5, String var6, int var7, int var8) {
      if (var1 == null) {
         throw new NullPointerException("premasterSecret must not be null");
      } else {
         this.premasterSecret = var1;
         this.majorVersion = checkVersion(var2);
         this.minorVersion = checkVersion(var3);
         this.clientRandom = (byte[])var4.clone();
         this.serverRandom = (byte[])var5.clone();
         this.prfHashAlg = var6;
         this.prfHashLength = var7;
         this.prfBlockSize = var8;
      }
   }

   static int checkVersion(int var0) {
      if (var0 >= 0 && var0 <= 255) {
         return var0;
      } else {
         throw new IllegalArgumentException("Version must be between 0 and 255");
      }
   }

   public SecretKey getPremasterSecret() {
      return this.premasterSecret;
   }

   public int getMajorVersion() {
      return this.majorVersion;
   }

   public int getMinorVersion() {
      return this.minorVersion;
   }

   public byte[] getClientRandom() {
      return (byte[])this.clientRandom.clone();
   }

   public byte[] getServerRandom() {
      return (byte[])this.serverRandom.clone();
   }

   public String getPRFHashAlg() {
      return this.prfHashAlg;
   }

   public int getPRFHashLength() {
      return this.prfHashLength;
   }

   public int getPRFBlockSize() {
      return this.prfBlockSize;
   }
}
