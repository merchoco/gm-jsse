package cn.gmssl.sun.security.internal.spec;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;

/** @deprecated */
@Deprecated
public class TlsKeyMaterialParameterSpec implements AlgorithmParameterSpec {
   private final SecretKey masterSecret;
   private final int majorVersion;
   private final int minorVersion;
   private final byte[] clientRandom;
   private final byte[] serverRandom;
   private final String cipherAlgorithm;
   private final int cipherKeyLength;
   private final int ivLength;
   private final int macKeyLength;
   private final int expandedCipherKeyLength;
   private final String prfHashAlg;
   private final int prfHashLength;
   private final int prfBlockSize;

   public TlsKeyMaterialParameterSpec(SecretKey var1, int var2, int var3, byte[] var4, byte[] var5, String var6, int var7, int var8, int var9, int var10, String var11, int var12, int var13) {
      if (!var1.getAlgorithm().equals("TlsMasterSecret")) {
         throw new IllegalArgumentException("Not a TLS master secret");
      } else if (var6 == null) {
         throw new NullPointerException();
      } else {
         this.masterSecret = var1;
         this.majorVersion = TlsMasterSecretParameterSpec.checkVersion(var2);
         this.minorVersion = TlsMasterSecretParameterSpec.checkVersion(var3);
         this.clientRandom = (byte[])var4.clone();
         this.serverRandom = (byte[])var5.clone();
         this.cipherAlgorithm = var6;
         this.cipherKeyLength = checkSign(var7);
         this.expandedCipherKeyLength = checkSign(var8);
         this.ivLength = checkSign(var9);
         this.macKeyLength = checkSign(var10);
         this.prfHashAlg = var11;
         this.prfHashLength = var12;
         this.prfBlockSize = var13;
      }
   }

   private static int checkSign(int var0) {
      if (var0 < 0) {
         throw new IllegalArgumentException("Value must not be negative");
      } else {
         return var0;
      }
   }

   public SecretKey getMasterSecret() {
      return this.masterSecret;
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

   public String getCipherAlgorithm() {
      return this.cipherAlgorithm;
   }

   public int getCipherKeyLength() {
      return this.cipherKeyLength;
   }

   public int getExpandedCipherKeyLength() {
      return this.majorVersion >= 3 && this.minorVersion >= 2 ? 0 : this.expandedCipherKeyLength;
   }

   public int getIvLength() {
      return this.majorVersion >= 3 && this.minorVersion >= 2 ? 0 : this.ivLength;
   }

   public int getMacKeyLength() {
      return this.macKeyLength;
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
