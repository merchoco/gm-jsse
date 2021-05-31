package cn.gmssl.crypto.impl.sm2;

import java.io.IOException;
import java.math.BigInteger;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERInteger;
import org.bc.asn1.DERSequence;
import org.bc.jcajce.provider.asymmetric.util.DSAEncoder;

public class StdDSAEncoder implements DSAEncoder {
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
}
