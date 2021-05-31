package cn.gmssl.com.sun.crypto.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.PSource.PSpecified;
import sun.security.util.Debug;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

public final class OAEPParameters extends AlgorithmParametersSpi {
   private String mdName;
   private MGF1ParameterSpec mgfSpec;
   private byte[] p;
   private static ObjectIdentifier OID_MGF1;
   private static ObjectIdentifier OID_PSpecified;

   static {
      try {
         OID_MGF1 = new ObjectIdentifier(new int[]{1, 2, 840, 113549, 1, 1, 8});
      } catch (IOException var2) {
         OID_MGF1 = null;
      }

      try {
         OID_PSpecified = new ObjectIdentifier(new int[]{1, 2, 840, 113549, 1, 1, 9});
      } catch (IOException var1) {
         OID_PSpecified = null;
      }

   }

   protected void engineInit(AlgorithmParameterSpec var1) throws InvalidParameterSpecException {
      if (!(var1 instanceof OAEPParameterSpec)) {
         throw new InvalidParameterSpecException("Inappropriate parameter specification");
      } else {
         OAEPParameterSpec var2 = (OAEPParameterSpec)var1;
         this.mdName = var2.getDigestAlgorithm();
         String var3 = var2.getMGFAlgorithm();
         if (!var3.equalsIgnoreCase("MGF1")) {
            throw new InvalidParameterSpecException("Unsupported mgf " + var3 + "; MGF1 only");
         } else {
            AlgorithmParameterSpec var4 = var2.getMGFParameters();
            if (!(var4 instanceof MGF1ParameterSpec)) {
               throw new InvalidParameterSpecException("Inappropriate mgf parameters; non-null MGF1ParameterSpec only");
            } else {
               this.mgfSpec = (MGF1ParameterSpec)var4;
               PSource var5 = var2.getPSource();
               if (var5.getAlgorithm().equals("PSpecified")) {
                  this.p = ((PSpecified)var5).getValue();
               } else {
                  throw new InvalidParameterSpecException("Unsupported pSource " + var5.getAlgorithm() + "; PSpecified only");
               }
            }
         }
      }
   }

   private static String convertToStandardName(String var0) {
      if (var0.equals("SHA")) {
         return "SHA-1";
      } else if (var0.equals("SHA256")) {
         return "SHA-256";
      } else if (var0.equals("SHA384")) {
         return "SHA-384";
      } else {
         return var0.equals("SHA512") ? "SHA-512" : var0;
      }
   }

   protected void engineInit(byte[] var1) throws IOException {
      DerInputStream var2 = new DerInputStream(var1);
      this.mdName = "SHA-1";
      this.mgfSpec = MGF1ParameterSpec.SHA1;
      this.p = new byte[0];
      DerValue[] var3 = var2.getSequence(3);

      for(int var4 = 0; var4 < var3.length; ++var4) {
         DerValue var5 = var3[var4];
         if (var5.isContextSpecific((byte)0)) {
            this.mdName = convertToStandardName(AlgorithmId.parse(var5.data.getDerValue()).getName());
         } else {
            AlgorithmId var6;
            if (var5.isContextSpecific((byte)1)) {
               var6 = AlgorithmId.parse(var5.data.getDerValue());
               if (!var6.getOID().equals(OID_MGF1)) {
                  throw new IOException("Only MGF1 mgf is supported");
               }

               AlgorithmId var7 = AlgorithmId.parse(new DerValue(var6.getEncodedParams()));
               String var8 = convertToStandardName(var7.getName());
               if (var8.equals("SHA-1")) {
                  this.mgfSpec = MGF1ParameterSpec.SHA1;
               } else if (var8.equals("SHA-256")) {
                  this.mgfSpec = MGF1ParameterSpec.SHA256;
               } else if (var8.equals("SHA-384")) {
                  this.mgfSpec = MGF1ParameterSpec.SHA384;
               } else {
                  if (!var8.equals("SHA-512")) {
                     throw new IOException("Unrecognized message digest algorithm");
                  }

                  this.mgfSpec = MGF1ParameterSpec.SHA512;
               }
            } else {
               if (!var5.isContextSpecific((byte)2)) {
                  throw new IOException("Invalid encoded OAEPParameters");
               }

               var6 = AlgorithmId.parse(var5.data.getDerValue());
               if (!var6.getOID().equals(OID_PSpecified)) {
                  throw new IOException("Wrong OID for pSpecified");
               }

               DerInputStream var9 = new DerInputStream(var6.getEncodedParams());
               this.p = var9.getOctetString();
               if (var9.available() != 0) {
                  throw new IOException("Extra data for pSpecified");
               }
            }
         }
      }

   }

   protected void engineInit(byte[] var1, String var2) throws IOException {
      if (var2 != null && !var2.equalsIgnoreCase("ASN.1")) {
         throw new IllegalArgumentException("Only support ASN.1 format");
      } else {
         this.engineInit(var1);
      }
   }

   protected AlgorithmParameterSpec engineGetParameterSpec(Class var1) throws InvalidParameterSpecException {
      if (OAEPParameterSpec.class.isAssignableFrom(var1)) {
         return new OAEPParameterSpec(this.mdName, "MGF1", this.mgfSpec, new PSpecified(this.p));
      } else {
         throw new InvalidParameterSpecException("Inappropriate parameter specification");
      }
   }

   protected byte[] engineGetEncoded() throws IOException {
      DerOutputStream var1 = new DerOutputStream();

      AlgorithmId var4;
      try {
         var4 = AlgorithmId.get(this.mdName);
      } catch (NoSuchAlgorithmException var9) {
         throw new IOException("AlgorithmId " + this.mdName + " impl not found");
      }

      DerOutputStream var2 = new DerOutputStream();
      var4.derEncode(var2);
      var1.write(DerValue.createTag((byte)-128, true, (byte)0), var2);
      var2 = new DerOutputStream();
      var2.putOID(OID_MGF1);

      AlgorithmId var5;
      try {
         var5 = AlgorithmId.get(this.mgfSpec.getDigestAlgorithm());
      } catch (NoSuchAlgorithmException var8) {
         throw new IOException("AlgorithmId " + this.mgfSpec.getDigestAlgorithm() + " impl not found");
      }

      var5.encode(var2);
      DerOutputStream var3 = new DerOutputStream();
      var3.write((byte)48, var2);
      var1.write(DerValue.createTag((byte)-128, true, (byte)1), var3);
      var2 = new DerOutputStream();
      var2.putOID(OID_PSpecified);
      var2.putOctetString(this.p);
      var3 = new DerOutputStream();
      var3.write((byte)48, var2);
      var1.write(DerValue.createTag((byte)-128, true, (byte)2), var3);
      DerOutputStream var6 = new DerOutputStream();
      var6.write((byte)48, var1);
      byte[] var7 = var6.toByteArray();
      var6.close();
      return var7;
   }

   protected byte[] engineGetEncoded(String var1) throws IOException {
      if (var1 != null && !var1.equalsIgnoreCase("ASN.1")) {
         throw new IllegalArgumentException("Only support ASN.1 format");
      } else {
         return this.engineGetEncoded();
      }
   }

   protected String engineToString() {
      StringBuffer var1 = new StringBuffer();
      var1.append("MD: " + this.mdName + "\n");
      var1.append("MGF: MGF1" + this.mgfSpec.getDigestAlgorithm() + "\n");
      var1.append("PSource: PSpecified " + (this.p.length == 0 ? "" : Debug.toHexString(new BigInteger(this.p))) + "\n");
      return var1.toString();
   }
}
