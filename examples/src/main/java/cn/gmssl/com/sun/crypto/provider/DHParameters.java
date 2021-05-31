package cn.gmssl.com.sun.crypto.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.DHParameterSpec;
import sun.security.util.Debug;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

public final class DHParameters extends AlgorithmParametersSpi {
   private BigInteger p;
   private BigInteger g;
   private int l;

   public DHParameters() {
      this.p = BigInteger.ZERO;
      this.g = BigInteger.ZERO;
      this.l = 0;
   }

   protected void engineInit(AlgorithmParameterSpec var1) throws InvalidParameterSpecException {
      if (!(var1 instanceof DHParameterSpec)) {
         throw new InvalidParameterSpecException("Inappropriate parameter specification");
      } else {
         this.p = ((DHParameterSpec)var1).getP();
         this.g = ((DHParameterSpec)var1).getG();
         this.l = ((DHParameterSpec)var1).getL();
      }
   }

   protected void engineInit(byte[] var1) throws IOException {
      try {
         DerValue var2 = new DerValue(var1);
         if (var2.tag != 48) {
            throw new IOException("DH params parsing error");
         } else {
            var2.data.reset();
            this.p = var2.data.getBigInteger();
            this.g = var2.data.getBigInteger();
            if (var2.data.available() != 0) {
               this.l = var2.data.getInteger();
            }

            if (var2.data.available() != 0) {
               throw new IOException("DH parameter parsing error: Extra data");
            }
         }
      } catch (NumberFormatException var3) {
         throw new IOException("Private-value length too big");
      }
   }

   protected void engineInit(byte[] var1, String var2) throws IOException {
      this.engineInit(var1);
   }

   protected AlgorithmParameterSpec engineGetParameterSpec(Class var1) throws InvalidParameterSpecException {
      if (DHParameterSpec.class.isAssignableFrom(var1)) {
         return new DHParameterSpec(this.p, this.g, this.l);
      } else {
         throw new InvalidParameterSpecException("Inappropriate parameter Specification");
      }
   }

   protected byte[] engineGetEncoded() throws IOException {
      DerOutputStream var1 = new DerOutputStream();
      DerOutputStream var2 = new DerOutputStream();
      var2.putInteger(this.p);
      var2.putInteger(this.g);
      if (this.l > 0) {
         var2.putInteger(this.l);
      }

      var1.write((byte)48, var2);
      byte[] var3 = var1.toByteArray();
      var1.close();
      return var3;
   }

   protected byte[] engineGetEncoded(String var1) throws IOException {
      return this.engineGetEncoded();
   }

   protected String engineToString() {
      String var1 = System.getProperty("line.separator");
      StringBuffer var2 = new StringBuffer("SunJCE Diffie-Hellman Parameters:" + var1 + "p:" + var1 + Debug.toHexString(this.p) + var1 + "g:" + var1 + Debug.toHexString(this.g));
      if (this.l != 0) {
         var2.append(var1 + "l:" + var1 + "    " + this.l);
      }

      return var2.toString();
   }
}
