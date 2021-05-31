package org.bc.asn1.nist;

import java.util.Enumeration;
import java.util.Hashtable;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.sec.SECNamedCurves;
import org.bc.asn1.sec.SECObjectIdentifiers;
import org.bc.asn1.x9.X9ECParameters;
import org.bc.util.Strings;

public class NISTNamedCurves {
   static final Hashtable objIds = new Hashtable();
   static final Hashtable names = new Hashtable();

   static {
      defineCurve("B-571", SECObjectIdentifiers.sect571r1);
      defineCurve("B-409", SECObjectIdentifiers.sect409r1);
      defineCurve("B-283", SECObjectIdentifiers.sect283r1);
      defineCurve("B-233", SECObjectIdentifiers.sect233r1);
      defineCurve("B-163", SECObjectIdentifiers.sect163r2);
      defineCurve("P-521", SECObjectIdentifiers.secp521r1);
      defineCurve("P-384", SECObjectIdentifiers.secp384r1);
      defineCurve("P-256", SECObjectIdentifiers.secp256r1);
      defineCurve("P-224", SECObjectIdentifiers.secp224r1);
      defineCurve("P-192", SECObjectIdentifiers.secp192r1);
   }

   static void defineCurve(String var0, ASN1ObjectIdentifier var1) {
      objIds.put(var0, var1);
      names.put(var1, var0);
   }

   public static X9ECParameters getByName(String var0) {
      ASN1ObjectIdentifier var1 = (ASN1ObjectIdentifier)objIds.get(Strings.toUpperCase(var0));
      return var1 != null ? getByOID(var1) : null;
   }

   public static X9ECParameters getByOID(ASN1ObjectIdentifier var0) {
      return SECNamedCurves.getByOID(var0);
   }

   public static ASN1ObjectIdentifier getOID(String var0) {
      return (ASN1ObjectIdentifier)objIds.get(Strings.toUpperCase(var0));
   }

   public static String getName(ASN1ObjectIdentifier var0) {
      return (String)names.get(var0);
   }

   public static Enumeration getNames() {
      return objIds.keys();
   }
}
