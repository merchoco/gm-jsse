package cn.gmssl.security.ec;

import java.io.IOException;
import java.io.ObjectStreamException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyRep;
import java.security.KeyRep.Type;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509Key;

public final class ECPublicKeyImpl extends X509Key implements ECPublicKey {
   private static final long serialVersionUID = -2462037275160462289L;
   private ECPoint w;
   private ECParameterSpec params;

   public ECPublicKeyImpl(ECPoint var1, ECParameterSpec var2) throws InvalidKeyException {
      this.w = var1;
      this.params = var2;
      this.algid = new AlgorithmId(AlgorithmId.EC_oid, ECParameters.getAlgorithmParameters(var2));
      this.key = ECParameters.encodePoint(var1, var2.getCurve());
   }

   public ECPublicKeyImpl(byte[] var1) throws InvalidKeyException {
      this.decode(var1);
   }

   public String getAlgorithm() {
      return "EC";
   }

   public ECPoint getW() {
      return this.w;
   }

   public ECParameterSpec getParams() {
      return this.params;
   }

   public byte[] getEncodedPublicValue() {
      return (byte[])this.key.clone();
   }

   protected void parseKeyBits() throws InvalidKeyException {
      try {
         AlgorithmParameters var1 = this.algid.getParameters();
         this.params = (ECParameterSpec)var1.getParameterSpec(ECParameterSpec.class);
         this.w = ECParameters.decodePoint(this.key, this.params.getCurve());
      } catch (IOException var2) {
         throw new InvalidKeyException("Invalid EC key", var2);
      } catch (InvalidParameterSpecException var3) {
         throw new InvalidKeyException("Invalid EC key", var3);
      }
   }

   public String toString() {
      return "Sun EC public key, " + this.params.getCurve().getField().getFieldSize() + " bits\n  public x coord: " + this.w.getAffineX() + "\n  public y coord: " + this.w.getAffineY() + "\n  parameters: " + this.params;
   }

   protected Object writeReplace() throws ObjectStreamException {
      return new KeyRep(Type.PUBLIC, this.getAlgorithm(), this.getFormat(), this.getEncoded());
   }
}
