package org.bc.jcajce.provider.asymmetric.ec;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERInteger;
import org.bc.asn1.DERSequence;
import org.bc.crypto.DSA;
import org.bc.crypto.Digest;
import org.bc.crypto.digests.NullDigest;
import org.bc.crypto.digests.RIPEMD160Digest;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.digests.SHA224Digest;
import org.bc.crypto.digests.SHA256Digest;
import org.bc.crypto.digests.SHA384Digest;
import org.bc.crypto.digests.SHA512Digest;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.crypto.signers.ECDSASigner;
import org.bc.crypto.signers.ECNRSigner;
import org.bc.jcajce.provider.asymmetric.util.DSABase;
import org.bc.jcajce.provider.asymmetric.util.DSAEncoder;

public class SignatureSpi extends DSABase {
   SignatureSpi(Digest var1, DSA var2, DSAEncoder var3) {
      super(var1, var2, var3);
   }

   protected void engineInitVerify(PublicKey var1) throws InvalidKeyException {
      AsymmetricKeyParameter var2 = ECUtil.generatePublicKeyParameter(var1);
      this.digest.reset();
      this.signer.init(false, var2);
   }

   protected void engineInitSign(PrivateKey var1) throws InvalidKeyException {
      AsymmetricKeyParameter var2 = ECUtil.generatePrivateKeyParameter(var1);
      this.digest.reset();
      if (this.appRandom != null) {
         this.signer.init(true, new ParametersWithRandom(var2, this.appRandom));
      } else {
         this.signer.init(true, var2);
      }

   }

   private static class CVCDSAEncoder implements DSAEncoder {
      private CVCDSAEncoder() {
      }

      public byte[] encode(BigInteger var1, BigInteger var2) throws IOException {
         byte[] var3 = this.makeUnsigned(var1);
         byte[] var4 = this.makeUnsigned(var2);
         byte[] var5;
         if (var3.length > var4.length) {
            var5 = new byte[var3.length * 2];
         } else {
            var5 = new byte[var4.length * 2];
         }

         System.arraycopy(var3, 0, var5, var5.length / 2 - var3.length, var3.length);
         System.arraycopy(var4, 0, var5, var5.length - var4.length, var4.length);
         return var5;
      }

      private byte[] makeUnsigned(BigInteger var1) {
         byte[] var2 = var1.toByteArray();
         if (var2[0] == 0) {
            byte[] var3 = new byte[var2.length - 1];
            System.arraycopy(var2, 1, var3, 0, var3.length);
            return var3;
         } else {
            return var2;
         }
      }

      public BigInteger[] decode(byte[] var1) throws IOException {
         BigInteger[] var2 = new BigInteger[2];
         byte[] var3 = new byte[var1.length / 2];
         byte[] var4 = new byte[var1.length / 2];
         System.arraycopy(var1, 0, var3, 0, var3.length);
         System.arraycopy(var1, var3.length, var4, 0, var4.length);
         var2[0] = new BigInteger(1, var3);
         var2[1] = new BigInteger(1, var4);
         return var2;
      }

      // $FF: synthetic method
      CVCDSAEncoder(SignatureSpi.CVCDSAEncoder var1) {
         this();
      }
   }

   private static class StdDSAEncoder implements DSAEncoder {
      private StdDSAEncoder() {
      }

      public byte[] encode(BigInteger var1, BigInteger var2) throws IOException {
         ASN1EncodableVector var3 = new ASN1EncodableVector();
         var3.add(new DERInteger(var1));
         var3.add(new DERInteger(var2));
         return (new DERSequence(var3)).getEncoded("DER");
      }

      public BigInteger[] decode(byte[] var1) throws IOException {
         ASN1Sequence var2 = (ASN1Sequence)ASN1Primitive.fromByteArray(var1);
         BigInteger[] var3 = new BigInteger[]{((DERInteger)var2.getObjectAt(0)).getValue(), ((DERInteger)var2.getObjectAt(1)).getValue()};
         return var3;
      }

      // $FF: synthetic method
      StdDSAEncoder(SignatureSpi.StdDSAEncoder var1) {
         this();
      }
   }

   public static class ecCVCDSA extends SignatureSpi {
      public ecCVCDSA() {
         super(new SHA1Digest(), new ECDSASigner(), new SignatureSpi.CVCDSAEncoder((SignatureSpi.CVCDSAEncoder)null));
      }
   }

   public static class ecCVCDSA224 extends SignatureSpi {
      public ecCVCDSA224() {
         super(new SHA224Digest(), new ECDSASigner(), new SignatureSpi.CVCDSAEncoder((SignatureSpi.CVCDSAEncoder)null));
      }
   }

   public static class ecCVCDSA256 extends SignatureSpi {
      public ecCVCDSA256() {
         super(new SHA256Digest(), new ECDSASigner(), new SignatureSpi.CVCDSAEncoder((SignatureSpi.CVCDSAEncoder)null));
      }
   }

   public static class ecDSA extends SignatureSpi {
      public ecDSA() {
         super(new SHA1Digest(), new ECDSASigner(), new SignatureSpi.StdDSAEncoder((SignatureSpi.StdDSAEncoder)null));
      }
   }

   public static class ecDSA224 extends SignatureSpi {
      public ecDSA224() {
         super(new SHA224Digest(), new ECDSASigner(), new SignatureSpi.StdDSAEncoder((SignatureSpi.StdDSAEncoder)null));
      }
   }

   public static class ecDSA256 extends SignatureSpi {
      public ecDSA256() {
         super(new SHA256Digest(), new ECDSASigner(), new SignatureSpi.StdDSAEncoder((SignatureSpi.StdDSAEncoder)null));
      }
   }

   public static class ecDSA384 extends SignatureSpi {
      public ecDSA384() {
         super(new SHA384Digest(), new ECDSASigner(), new SignatureSpi.StdDSAEncoder((SignatureSpi.StdDSAEncoder)null));
      }
   }

   public static class ecDSA512 extends SignatureSpi {
      public ecDSA512() {
         super(new SHA512Digest(), new ECDSASigner(), new SignatureSpi.StdDSAEncoder((SignatureSpi.StdDSAEncoder)null));
      }
   }

   public static class ecDSARipeMD160 extends SignatureSpi {
      public ecDSARipeMD160() {
         super(new RIPEMD160Digest(), new ECDSASigner(), new SignatureSpi.StdDSAEncoder((SignatureSpi.StdDSAEncoder)null));
      }
   }

   public static class ecDSAnone extends SignatureSpi {
      public ecDSAnone() {
         super(new NullDigest(), new ECDSASigner(), new SignatureSpi.StdDSAEncoder((SignatureSpi.StdDSAEncoder)null));
      }
   }

   public static class ecNR extends SignatureSpi {
      public ecNR() {
         super(new SHA1Digest(), new ECNRSigner(), new SignatureSpi.StdDSAEncoder((SignatureSpi.StdDSAEncoder)null));
      }
   }

   public static class ecNR224 extends SignatureSpi {
      public ecNR224() {
         super(new SHA224Digest(), new ECNRSigner(), new SignatureSpi.StdDSAEncoder((SignatureSpi.StdDSAEncoder)null));
      }
   }

   public static class ecNR256 extends SignatureSpi {
      public ecNR256() {
         super(new SHA256Digest(), new ECNRSigner(), new SignatureSpi.StdDSAEncoder((SignatureSpi.StdDSAEncoder)null));
      }
   }

   public static class ecNR384 extends SignatureSpi {
      public ecNR384() {
         super(new SHA384Digest(), new ECNRSigner(), new SignatureSpi.StdDSAEncoder((SignatureSpi.StdDSAEncoder)null));
      }
   }

   public static class ecNR512 extends SignatureSpi {
      public ecNR512() {
         super(new SHA512Digest(), new ECNRSigner(), new SignatureSpi.StdDSAEncoder((SignatureSpi.StdDSAEncoder)null));
      }
   }
}
