package org.bc.jce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERInteger;
import org.bc.asn1.oiw.ElGamalParameter;
import org.bc.asn1.oiw.OIWObjectIdentifiers;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.crypto.params.ElGamalPublicKeyParameters;
import org.bc.jcajce.provider.asymmetric.util.KeyUtil;
import org.bc.jce.interfaces.ElGamalPublicKey;
import org.bc.jce.spec.ElGamalParameterSpec;
import org.bc.jce.spec.ElGamalPublicKeySpec;

public class JCEElGamalPublicKey implements ElGamalPublicKey, DHPublicKey {
   static final long serialVersionUID = 8712728417091216948L;
   private BigInteger y;
   private ElGamalParameterSpec elSpec;

   JCEElGamalPublicKey(ElGamalPublicKeySpec var1) {
      this.y = var1.getY();
      this.elSpec = new ElGamalParameterSpec(var1.getParams().getP(), var1.getParams().getG());
   }

   JCEElGamalPublicKey(DHPublicKeySpec var1) {
      this.y = var1.getY();
      this.elSpec = new ElGamalParameterSpec(var1.getP(), var1.getG());
   }

   JCEElGamalPublicKey(ElGamalPublicKey var1) {
      this.y = var1.getY();
      this.elSpec = var1.getParameters();
   }

   JCEElGamalPublicKey(DHPublicKey var1) {
      this.y = var1.getY();
      this.elSpec = new ElGamalParameterSpec(var1.getParams().getP(), var1.getParams().getG());
   }

   JCEElGamalPublicKey(ElGamalPublicKeyParameters var1) {
      this.y = var1.getY();
      this.elSpec = new ElGamalParameterSpec(var1.getParameters().getP(), var1.getParameters().getG());
   }

   JCEElGamalPublicKey(BigInteger var1, ElGamalParameterSpec var2) {
      this.y = var1;
      this.elSpec = var2;
   }

   JCEElGamalPublicKey(SubjectPublicKeyInfo var1) {
      ElGamalParameter var2 = new ElGamalParameter((ASN1Sequence)var1.getAlgorithmId().getParameters());
      DERInteger var3 = null;

      try {
         var3 = (DERInteger)var1.parsePublicKey();
      } catch (IOException var5) {
         throw new IllegalArgumentException("invalid info structure in DSA public key");
      }

      this.y = var3.getValue();
      this.elSpec = new ElGamalParameterSpec(var2.getP(), var2.getG());
   }

   public String getAlgorithm() {
      return "ElGamal";
   }

   public String getFormat() {
      return "X.509";
   }

   public byte[] getEncoded() {
      return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(this.elSpec.getP(), this.elSpec.getG())), (ASN1Encodable)(new DERInteger(this.y)));
   }

   public ElGamalParameterSpec getParameters() {
      return this.elSpec;
   }

   public DHParameterSpec getParams() {
      return new DHParameterSpec(this.elSpec.getP(), this.elSpec.getG());
   }

   public BigInteger getY() {
      return this.y;
   }

   private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
      this.y = (BigInteger)var1.readObject();
      this.elSpec = new ElGamalParameterSpec((BigInteger)var1.readObject(), (BigInteger)var1.readObject());
   }

   private void writeObject(ObjectOutputStream var1) throws IOException {
      var1.writeObject(this.getY());
      var1.writeObject(this.elSpec.getP());
      var1.writeObject(this.elSpec.getG());
   }
}
