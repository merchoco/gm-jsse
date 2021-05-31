package cn.gmssl.sun.security.internal.spec;

import cn.gmssl.sun.security.ssl.ProtocolVersion;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;

/** @deprecated */
@Deprecated
public class TlsPrfParameterSpec implements AlgorithmParameterSpec {
   private final SecretKey secret;
   private final String label;
   private final byte[] seed;
   private final int outputLength;
   private final String prfHashAlg;
   private final int prfHashLength;
   private final int prfBlockSize;
   private final ProtocolVersion protocolVersion;

   public TlsPrfParameterSpec(SecretKey var1, String var2, byte[] var3, int var4, String var5, int var6, int var7, ProtocolVersion var8) {
      if (var2 != null && var3 != null) {
         if (var4 <= 0) {
            throw new IllegalArgumentException("outputLength must be positive");
         } else {
            this.secret = var1;
            this.label = var2;
            this.seed = (byte[])var3.clone();
            this.outputLength = var4;
            this.prfHashAlg = var5;
            this.prfHashLength = var6;
            this.prfBlockSize = var7;
            this.protocolVersion = var8;
         }
      } else {
         throw new NullPointerException("label and seed must not be null");
      }
   }

   public SecretKey getSecret() {
      return this.secret;
   }

   public String getLabel() {
      return this.label;
   }

   public byte[] getSeed() {
      return (byte[])this.seed.clone();
   }

   public int getOutputLength() {
      return this.outputLength;
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

   public ProtocolVersion getProtocolVersion() {
      return this.protocolVersion;
   }
}
