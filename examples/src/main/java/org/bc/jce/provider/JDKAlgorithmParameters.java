package org.bc.jce.provider;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.PBEParameterSpec;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERInteger;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;
import org.bc.asn1.pkcs.PBKDF2Params;
import org.bc.asn1.pkcs.PKCS12PBEParams;
import org.bc.jce.spec.IESParameterSpec;

public abstract class JDKAlgorithmParameters extends AlgorithmParametersSpi {
   protected boolean isASN1FormatString(String var1) {
      return var1 == null || var1.equals("ASN.1");
   }

   protected AlgorithmParameterSpec engineGetParameterSpec(Class var1) throws InvalidParameterSpecException {
      if (var1 == null) {
         throw new NullPointerException("argument to getParameterSpec must not be null");
      } else {
         return this.localEngineGetParameterSpec(var1);
      }
   }

   protected abstract AlgorithmParameterSpec localEngineGetParameterSpec(Class var1) throws InvalidParameterSpecException;

   public static class IES extends JDKAlgorithmParameters {
      IESParameterSpec currentSpec;

      protected byte[] engineGetEncoded() {
         try {
            ASN1EncodableVector var1 = new ASN1EncodableVector();
            var1.add(new DEROctetString(this.currentSpec.getDerivationV()));
            var1.add(new DEROctetString(this.currentSpec.getEncodingV()));
            var1.add(new DERInteger((long)this.currentSpec.getMacKeySize()));
            return (new DERSequence(var1)).getEncoded("DER");
         } catch (IOException var2) {
            throw new RuntimeException("Error encoding IESParameters");
         }
      }

      protected byte[] engineGetEncoded(String var1) {
         return !this.isASN1FormatString(var1) && !var1.equalsIgnoreCase("X.509") ? null : this.engineGetEncoded();
      }

      protected AlgorithmParameterSpec localEngineGetParameterSpec(Class var1) throws InvalidParameterSpecException {
         if (var1 == IESParameterSpec.class) {
            return this.currentSpec;
         } else {
            throw new InvalidParameterSpecException("unknown parameter spec passed to ElGamal parameters object.");
         }
      }

      protected void engineInit(AlgorithmParameterSpec var1) throws InvalidParameterSpecException {
         if (!(var1 instanceof IESParameterSpec)) {
            throw new InvalidParameterSpecException("IESParameterSpec required to initialise a IES algorithm parameters object");
         } else {
            this.currentSpec = (IESParameterSpec)var1;
         }
      }

      protected void engineInit(byte[] var1) throws IOException {
         try {
            ASN1Sequence var2 = (ASN1Sequence)ASN1Primitive.fromByteArray(var1);
            this.currentSpec = new IESParameterSpec(((ASN1OctetString)var2.getObjectAt(0)).getOctets(), ((ASN1OctetString)var2.getObjectAt(0)).getOctets(), ((DERInteger)var2.getObjectAt(0)).getValue().intValue());
         } catch (ClassCastException var3) {
            throw new IOException("Not a valid IES Parameter encoding.");
         } catch (ArrayIndexOutOfBoundsException var4) {
            throw new IOException("Not a valid IES Parameter encoding.");
         }
      }

      protected void engineInit(byte[] var1, String var2) throws IOException {
         if (!this.isASN1FormatString(var2) && !var2.equalsIgnoreCase("X.509")) {
            throw new IOException("Unknown parameter format " + var2);
         } else {
            this.engineInit(var1);
         }
      }

      protected String engineToString() {
         return "IES Parameters";
      }
   }

   public static class PBKDF2 extends JDKAlgorithmParameters {
      PBKDF2Params params;

      protected byte[] engineGetEncoded() {
         try {
            return this.params.getEncoded("DER");
         } catch (IOException var2) {
            throw new RuntimeException("Oooops! " + var2.toString());
         }
      }

      protected byte[] engineGetEncoded(String var1) {
         return this.isASN1FormatString(var1) ? this.engineGetEncoded() : null;
      }

      protected AlgorithmParameterSpec localEngineGetParameterSpec(Class var1) throws InvalidParameterSpecException {
         if (var1 == PBEParameterSpec.class) {
            return new PBEParameterSpec(this.params.getSalt(), this.params.getIterationCount().intValue());
         } else {
            throw new InvalidParameterSpecException("unknown parameter spec passed to PKCS12 PBE parameters object.");
         }
      }

      protected void engineInit(AlgorithmParameterSpec var1) throws InvalidParameterSpecException {
         if (!(var1 instanceof PBEParameterSpec)) {
            throw new InvalidParameterSpecException("PBEParameterSpec required to initialise a PKCS12 PBE parameters algorithm parameters object");
         } else {
            PBEParameterSpec var2 = (PBEParameterSpec)var1;
            this.params = new PBKDF2Params(var2.getSalt(), var2.getIterationCount());
         }
      }

      protected void engineInit(byte[] var1) throws IOException {
         this.params = PBKDF2Params.getInstance(ASN1Primitive.fromByteArray(var1));
      }

      protected void engineInit(byte[] var1, String var2) throws IOException {
         if (this.isASN1FormatString(var2)) {
            this.engineInit(var1);
         } else {
            throw new IOException("Unknown parameters format in PWRIKEK parameters object");
         }
      }

      protected String engineToString() {
         return "PBKDF2 Parameters";
      }
   }

   public static class PKCS12PBE extends JDKAlgorithmParameters {
      PKCS12PBEParams params;

      protected byte[] engineGetEncoded() {
         try {
            return this.params.getEncoded("DER");
         } catch (IOException var2) {
            throw new RuntimeException("Oooops! " + var2.toString());
         }
      }

      protected byte[] engineGetEncoded(String var1) {
         return this.isASN1FormatString(var1) ? this.engineGetEncoded() : null;
      }

      protected AlgorithmParameterSpec localEngineGetParameterSpec(Class var1) throws InvalidParameterSpecException {
         if (var1 == PBEParameterSpec.class) {
            return new PBEParameterSpec(this.params.getIV(), this.params.getIterations().intValue());
         } else {
            throw new InvalidParameterSpecException("unknown parameter spec passed to PKCS12 PBE parameters object.");
         }
      }

      protected void engineInit(AlgorithmParameterSpec var1) throws InvalidParameterSpecException {
         if (!(var1 instanceof PBEParameterSpec)) {
            throw new InvalidParameterSpecException("PBEParameterSpec required to initialise a PKCS12 PBE parameters algorithm parameters object");
         } else {
            PBEParameterSpec var2 = (PBEParameterSpec)var1;
            this.params = new PKCS12PBEParams(var2.getSalt(), var2.getIterationCount());
         }
      }

      protected void engineInit(byte[] var1) throws IOException {
         this.params = PKCS12PBEParams.getInstance(ASN1Primitive.fromByteArray(var1));
      }

      protected void engineInit(byte[] var1, String var2) throws IOException {
         if (this.isASN1FormatString(var2)) {
            this.engineInit(var1);
         } else {
            throw new IOException("Unknown parameters format in PKCS12 PBE parameters object");
         }
      }

      protected String engineToString() {
         return "PKCS12 PBE Parameters";
      }
   }
}
