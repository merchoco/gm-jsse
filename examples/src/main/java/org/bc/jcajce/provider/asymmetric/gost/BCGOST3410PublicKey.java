package org.bc.jcajce.provider.asymmetric.gost;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bc.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.crypto.params.GOST3410PublicKeyParameters;
import org.bc.jcajce.provider.asymmetric.util.KeyUtil;
import org.bc.jce.interfaces.GOST3410Params;
import org.bc.jce.interfaces.GOST3410PublicKey;
import org.bc.jce.spec.GOST3410ParameterSpec;
import org.bc.jce.spec.GOST3410PublicKeyParameterSetSpec;
import org.bc.jce.spec.GOST3410PublicKeySpec;

public class BCGOST3410PublicKey implements GOST3410PublicKey {
   static final long serialVersionUID = -6251023343619275990L;
   private BigInteger y;
   private transient GOST3410Params gost3410Spec;

   BCGOST3410PublicKey(GOST3410PublicKeySpec var1) {
      this.y = var1.getY();
      this.gost3410Spec = new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec(var1.getP(), var1.getQ(), var1.getA()));
   }

   BCGOST3410PublicKey(GOST3410PublicKey var1) {
      this.y = var1.getY();
      this.gost3410Spec = var1.getParameters();
   }

   BCGOST3410PublicKey(GOST3410PublicKeyParameters var1, GOST3410ParameterSpec var2) {
      this.y = var1.getY();
      this.gost3410Spec = var2;
   }

   BCGOST3410PublicKey(BigInteger var1, GOST3410ParameterSpec var2) {
      this.y = var1;
      this.gost3410Spec = var2;
   }

   BCGOST3410PublicKey(SubjectPublicKeyInfo var1) {
      GOST3410PublicKeyAlgParameters var2 = new GOST3410PublicKeyAlgParameters((ASN1Sequence)var1.getAlgorithmId().getParameters());

      try {
         DEROctetString var3 = (DEROctetString)var1.parsePublicKey();
         byte[] var4 = var3.getOctets();
         byte[] var5 = new byte[var4.length];
         int var6 = 0;

         while(true) {
            if (var6 == var4.length) {
               this.y = new BigInteger(1, var5);
               break;
            }

            var5[var6] = var4[var4.length - 1 - var6];
            ++var6;
         }
      } catch (IOException var7) {
         throw new IllegalArgumentException("invalid info structure in GOST3410 public key");
      }

      this.gost3410Spec = GOST3410ParameterSpec.fromPublicKeyAlg(var2);
   }

   public String getAlgorithm() {
      return "GOST3410";
   }

   public String getFormat() {
      return "X.509";
   }

   public byte[] getEncoded() {
      byte[] var2 = this.getY().toByteArray();
      byte[] var3;
      if (var2[0] == 0) {
         var3 = new byte[var2.length - 1];
      } else {
         var3 = new byte[var2.length];
      }

      for(int var4 = 0; var4 != var3.length; ++var4) {
         var3[var4] = var2[var2.length - 1 - var4];
      }

      try {
         SubjectPublicKeyInfo var1;
         if (this.gost3410Spec instanceof GOST3410ParameterSpec) {
            if (this.gost3410Spec.getEncryptionParamSetOID() != null) {
               var1 = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94, new GOST3410PublicKeyAlgParameters(new ASN1ObjectIdentifier(this.gost3410Spec.getPublicKeyParamSetOID()), new ASN1ObjectIdentifier(this.gost3410Spec.getDigestParamSetOID()), new ASN1ObjectIdentifier(this.gost3410Spec.getEncryptionParamSetOID()))), new DEROctetString(var3));
            } else {
               var1 = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94, new GOST3410PublicKeyAlgParameters(new ASN1ObjectIdentifier(this.gost3410Spec.getPublicKeyParamSetOID()), new ASN1ObjectIdentifier(this.gost3410Spec.getDigestParamSetOID()))), new DEROctetString(var3));
            }
         } else {
            var1 = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_94), new DEROctetString(var3));
         }

         return KeyUtil.getEncodedSubjectPublicKeyInfo(var1);
      } catch (IOException var5) {
         return null;
      }
   }

   public GOST3410Params getParameters() {
      return this.gost3410Spec;
   }

   public BigInteger getY() {
      return this.y;
   }

   public String toString() {
      StringBuffer var1 = new StringBuffer();
      String var2 = System.getProperty("line.separator");
      var1.append("GOST3410 Public Key").append(var2);
      var1.append("            y: ").append(this.getY().toString(16)).append(var2);
      return var1.toString();
   }

   public boolean equals(Object var1) {
      if (var1 instanceof BCGOST3410PublicKey) {
         BCGOST3410PublicKey var2 = (BCGOST3410PublicKey)var1;
         return this.y.equals(var2.y) && this.gost3410Spec.equals(var2.gost3410Spec);
      } else {
         return false;
      }
   }

   public int hashCode() {
      return this.y.hashCode() ^ this.gost3410Spec.hashCode();
   }

   private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
      var1.defaultReadObject();
      String var2 = (String)var1.readObject();
      if (var2 != null) {
         this.gost3410Spec = new GOST3410ParameterSpec(var2, (String)var1.readObject(), (String)var1.readObject());
      } else {
         this.gost3410Spec = new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec((BigInteger)var1.readObject(), (BigInteger)var1.readObject(), (BigInteger)var1.readObject()));
         var1.readObject();
         var1.readObject();
      }

   }

   private void writeObject(ObjectOutputStream var1) throws IOException {
      var1.defaultWriteObject();
      if (this.gost3410Spec.getPublicKeyParamSetOID() != null) {
         var1.writeObject(this.gost3410Spec.getPublicKeyParamSetOID());
         var1.writeObject(this.gost3410Spec.getDigestParamSetOID());
         var1.writeObject(this.gost3410Spec.getEncryptionParamSetOID());
      } else {
         var1.writeObject((Object)null);
         var1.writeObject(this.gost3410Spec.getPublicKeyParameters().getP());
         var1.writeObject(this.gost3410Spec.getPublicKeyParameters().getQ());
         var1.writeObject(this.gost3410Spec.getPublicKeyParameters().getA());
         var1.writeObject(this.gost3410Spec.getDigestParamSetOID());
         var1.writeObject(this.gost3410Spec.getEncryptionParamSetOID());
      }

   }
}
