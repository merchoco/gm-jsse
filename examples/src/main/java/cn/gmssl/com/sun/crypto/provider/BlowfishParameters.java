package cn.gmssl.com.sun.crypto.provider;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public final class BlowfishParameters extends AlgorithmParametersSpi {
   private BlockCipherParamsCore core = new BlockCipherParamsCore(8);

   protected void engineInit(AlgorithmParameterSpec var1) throws InvalidParameterSpecException {
      this.core.init(var1);
   }

   protected void engineInit(byte[] var1) throws IOException {
      this.core.init(var1);
   }

   protected void engineInit(byte[] var1, String var2) throws IOException {
      this.core.init(var1, var2);
   }

   protected AlgorithmParameterSpec engineGetParameterSpec(Class var1) throws InvalidParameterSpecException {
      return this.core.getParameterSpec(var1);
   }

   protected byte[] engineGetEncoded() throws IOException {
      return this.core.getEncoded();
   }

   protected byte[] engineGetEncoded(String var1) throws IOException {
      return this.core.getEncoded();
   }

   protected String engineToString() {
      return this.core.toString();
   }
}
