package org.bc.jce;

import java.util.Enumeration;
import java.util.Vector;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.nist.NISTNamedCurves;
import org.bc.asn1.sec.SECNamedCurves;
import org.bc.asn1.teletrust.TeleTrusTNamedCurves;
import org.bc.asn1.x9.X962NamedCurves;
import org.bc.asn1.x9.X9ECParameters;
import org.bc.jce.spec.ECNamedCurveParameterSpec;

public class ECNamedCurveTable {
   public static ECNamedCurveParameterSpec getParameterSpec(String var0) {
      X9ECParameters var1 = X962NamedCurves.getByName(var0);
      if (var1 == null) {
         try {
            var1 = X962NamedCurves.getByOID(new ASN1ObjectIdentifier(var0));
         } catch (IllegalArgumentException var5) {
            ;
         }
      }

      if (var1 == null) {
         var1 = SECNamedCurves.getByName(var0);
         if (var1 == null) {
            try {
               var1 = SECNamedCurves.getByOID(new ASN1ObjectIdentifier(var0));
            } catch (IllegalArgumentException var4) {
               ;
            }
         }
      }

      if (var1 == null) {
         var1 = TeleTrusTNamedCurves.getByName(var0);
         if (var1 == null) {
            try {
               var1 = TeleTrusTNamedCurves.getByOID(new ASN1ObjectIdentifier(var0));
            } catch (IllegalArgumentException var3) {
               ;
            }
         }
      }

      if (var1 == null) {
         var1 = NISTNamedCurves.getByName(var0);
      }

      return var1 == null ? null : new ECNamedCurveParameterSpec(var0, var1.getCurve(), var1.getG(), var1.getN(), var1.getH(), var1.getSeed());
   }

   public static Enumeration getNames() {
      Vector var0 = new Vector();
      addEnumeration(var0, X962NamedCurves.getNames());
      addEnumeration(var0, SECNamedCurves.getNames());
      addEnumeration(var0, NISTNamedCurves.getNames());
      addEnumeration(var0, TeleTrusTNamedCurves.getNames());
      return var0.elements();
   }

   private static void addEnumeration(Vector var0, Enumeration var1) {
      while(var1.hasMoreElements()) {
         var0.addElement(var1.nextElement());
      }

   }
}
