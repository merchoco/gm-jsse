package cn.gmssl.sun.security.internal.spec;

import java.security.spec.AlgorithmParameterSpec;

/** @deprecated */
@Deprecated
public class TlsRsaPremasterSecretParameterSpec implements AlgorithmParameterSpec {
   private final int majorVersion;
   private final int minorVersion;

   public TlsRsaPremasterSecretParameterSpec(int var1, int var2) {
      this.majorVersion = TlsMasterSecretParameterSpec.checkVersion(var1);
      this.minorVersion = TlsMasterSecretParameterSpec.checkVersion(var2);
   }

   public int getMajorVersion() {
      return this.majorVersion;
   }

   public int getMinorVersion() {
      return this.minorVersion;
   }
}
