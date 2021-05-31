package cn.gmssl.com.sun.crypto.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.PBEParameterSpec;
import sun.misc.HexDumpEncoder;
import sun.security.util.Debug;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

public final class PBEParameters extends AlgorithmParametersSpi {
   private byte[] salt = null;
   private int iCount = 0;

   protected void engineInit(AlgorithmParameterSpec var1) throws InvalidParameterSpecException {
      if (!(var1 instanceof PBEParameterSpec)) {
         throw new InvalidParameterSpecException("Inappropriate parameter specification");
      } else {
         this.salt = (byte[])((PBEParameterSpec)var1).getSalt().clone();
         this.iCount = ((PBEParameterSpec)var1).getIterationCount();
      }
   }

   protected void engineInit(byte[] var1) throws IOException {
      try {
         DerValue var2 = new DerValue(var1);
         if (var2.tag != 48) {
            throw new IOException("PBE parameter parsing error: not a sequence");
         } else {
            var2.data.reset();
            this.salt = var2.data.getOctetString();
            this.iCount = var2.data.getInteger();
            if (var2.data.available() != 0) {
               throw new IOException("PBE parameter parsing error: extra data");
            }
         }
      } catch (NumberFormatException var3) {
         throw new IOException("iteration count too big");
      }
   }

   protected void engineInit(byte[] var1, String var2) throws IOException {
      this.engineInit(var1);
   }

   protected AlgorithmParameterSpec engineGetParameterSpec(Class var1) throws InvalidParameterSpecException {
      if (PBEParameterSpec.class.isAssignableFrom(var1)) {
         return new PBEParameterSpec(this.salt, this.iCount);
      } else {
         throw new InvalidParameterSpecException("Inappropriate parameter specification");
      }
   }

   protected byte[] engineGetEncoded() throws IOException {
      DerOutputStream var1 = new DerOutputStream();
      DerOutputStream var2 = new DerOutputStream();
      var2.putOctetString(this.salt);
      var2.putInteger(this.iCount);
      var1.write((byte)48, var2);
      return var1.toByteArray();
   }

   protected byte[] engineGetEncoded(String var1) throws IOException {
      return this.engineGetEncoded();
   }

   protected String engineToString() {
      String var1 = System.getProperty("line.separator");
      String var2 = var1 + "    salt:" + var1 + "[";
      HexDumpEncoder var3 = new HexDumpEncoder();
      var2 = var2 + var3.encodeBuffer(this.salt);
      var2 = var2 + "]";
      return var2 + var1 + "    iterationCount:" + var1 + Debug.toHexString(BigInteger.valueOf((long)this.iCount)) + var1;
   }
}
