package org.bc.pqc.jcajce.provider.gmss;

import java.security.PublicKey;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.crypto.CipherParameters;
import org.bc.pqc.asn1.GMSSPublicKey;
import org.bc.pqc.asn1.PQCObjectIdentifiers;
import org.bc.pqc.asn1.ParSet;
import org.bc.pqc.crypto.gmss.GMSSParameters;
import org.bc.pqc.crypto.gmss.GMSSPublicKeyParameters;
import org.bc.pqc.jcajce.provider.util.KeyUtil;
import org.bc.pqc.jcajce.spec.GMSSPublicKeySpec;
import org.bc.util.encoders.Hex;

public class BCGMSSPublicKey implements CipherParameters, PublicKey {
   private static final long serialVersionUID = 1L;
   private byte[] publicKeyBytes;
   private GMSSParameters gmssParameterSet;
   private GMSSParameters gmssParams;

   public BCGMSSPublicKey(byte[] var1, GMSSParameters var2) {
      this.gmssParameterSet = var2;
      this.publicKeyBytes = var1;
   }

   protected BCGMSSPublicKey(GMSSPublicKeySpec var1) {
      this(var1.getPublicKey(), var1.getParameters());
   }

   public BCGMSSPublicKey(GMSSPublicKeyParameters var1) {
      this(var1.getPublicKey(), var1.getParameters());
   }

   public String getAlgorithm() {
      return "GMSS";
   }

   public byte[] getPublicKeyBytes() {
      return this.publicKeyBytes;
   }

   public GMSSParameters getParameterSet() {
      return this.gmssParameterSet;
   }

   public String toString() {
      String var1 = "GMSS public key : " + new String(Hex.encode(this.publicKeyBytes)) + "\n" + "Height of Trees: \n";

      for(int var2 = 0; var2 < this.gmssParameterSet.getHeightOfTrees().length; ++var2) {
         var1 = var1 + "Layer " + var2 + " : " + this.gmssParameterSet.getHeightOfTrees()[var2] + " WinternitzParameter: " + this.gmssParameterSet.getWinternitzParameter()[var2] + " K: " + this.gmssParameterSet.getK()[var2] + "\n";
      }

      return var1;
   }

   public byte[] getEncoded() {
      return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.gmss, (new ParSet(this.gmssParameterSet.getNumOfLayers(), this.gmssParameterSet.getHeightOfTrees(), this.gmssParameterSet.getWinternitzParameter(), this.gmssParameterSet.getK())).toASN1Primitive()), (ASN1Encodable)(new GMSSPublicKey(this.publicKeyBytes)));
   }

   public String getFormat() {
      return "X.509";
   }
}
