package org.bc.jcajce.provider.symmetric.util;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.IvParameterSpec;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.DEROctetString;
import org.bc.util.Arrays;

public class IvAlgorithmParameters extends BaseAlgorithmParameters {
   private byte[] iv;

   protected byte[] engineGetEncoded() throws IOException {
      return this.engineGetEncoded("ASN.1");
   }

   protected byte[] engineGetEncoded(String var1) throws IOException {
      if (this.isASN1FormatString(var1)) {
         return (new DEROctetString(this.engineGetEncoded("RAW"))).getEncoded();
      } else {
         return var1.equals("RAW") ? Arrays.clone(this.iv) : null;
      }
   }

   protected AlgorithmParameterSpec localEngineGetParameterSpec(Class var1) throws InvalidParameterSpecException {
      if (var1 == IvParameterSpec.class) {
         return new IvParameterSpec(this.iv);
      } else {
         throw new InvalidParameterSpecException("unknown parameter spec passed to IV parameters object.");
      }
   }

   protected void engineInit(AlgorithmParameterSpec var1) throws InvalidParameterSpecException {
      if (!(var1 instanceof IvParameterSpec)) {
         throw new InvalidParameterSpecException("IvParameterSpec required to initialise a IV parameters algorithm parameters object");
      } else {
         this.iv = ((IvParameterSpec)var1).getIV();
      }
   }

   protected void engineInit(byte[] var1) throws IOException {
      if (var1.length % 8 != 0 && var1[0] == 4 && var1[1] == var1.length - 2) {
         ASN1OctetString var2 = (ASN1OctetString)ASN1Primitive.fromByteArray(var1);
         var1 = var2.getOctets();
      }

      this.iv = Arrays.clone(var1);
   }

   protected void engineInit(byte[] var1, String var2) throws IOException {
      if (this.isASN1FormatString(var2)) {
         try {
            ASN1OctetString var3 = (ASN1OctetString)ASN1Primitive.fromByteArray(var1);
            this.engineInit(var3.getOctets());
         } catch (Exception var4) {
            throw new IOException("Exception decoding: " + var4);
         }
      } else if (var2.equals("RAW")) {
         this.engineInit(var1);
      } else {
         throw new IOException("Unknown parameters format in IV parameters object");
      }
   }

   protected String engineToString() {
      return "IV Parameters";
   }
}
