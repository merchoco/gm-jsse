package org.bc.asn1.smime;

import java.util.Enumeration;
import java.util.Vector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.cms.Attribute;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;

public class SMIMECapabilities extends ASN1Object {
   public static final ASN1ObjectIdentifier preferSignedData;
   public static final ASN1ObjectIdentifier canNotDecryptAny;
   public static final ASN1ObjectIdentifier sMIMECapabilitesVersions;
   public static final ASN1ObjectIdentifier dES_CBC;
   public static final ASN1ObjectIdentifier dES_EDE3_CBC;
   public static final ASN1ObjectIdentifier rC2_CBC;
   private ASN1Sequence capabilities;

   static {
      preferSignedData = PKCSObjectIdentifiers.preferSignedData;
      canNotDecryptAny = PKCSObjectIdentifiers.canNotDecryptAny;
      sMIMECapabilitesVersions = PKCSObjectIdentifiers.sMIMECapabilitiesVersions;
      dES_CBC = new ASN1ObjectIdentifier("1.3.14.3.2.7");
      dES_EDE3_CBC = PKCSObjectIdentifiers.des_EDE3_CBC;
      rC2_CBC = PKCSObjectIdentifiers.RC2_CBC;
   }

   public static SMIMECapabilities getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof SMIMECapabilities)) {
         if (var0 instanceof ASN1Sequence) {
            return new SMIMECapabilities((ASN1Sequence)var0);
         } else if (var0 instanceof Attribute) {
            return new SMIMECapabilities((ASN1Sequence)((Attribute)var0).getAttrValues().getObjectAt(0));
         } else {
            throw new IllegalArgumentException("unknown object in factory: " + var0.getClass().getName());
         }
      } else {
         return (SMIMECapabilities)var0;
      }
   }

   public SMIMECapabilities(ASN1Sequence var1) {
      this.capabilities = var1;
   }

   public Vector getCapabilities(ASN1ObjectIdentifier var1) {
      Enumeration var2 = this.capabilities.getObjects();
      Vector var3 = new Vector();
      SMIMECapability var4;
      if (var1 == null) {
         while(var2.hasMoreElements()) {
            var4 = SMIMECapability.getInstance(var2.nextElement());
            var3.addElement(var4);
         }
      } else {
         while(var2.hasMoreElements()) {
            var4 = SMIMECapability.getInstance(var2.nextElement());
            if (var1.equals(var4.getCapabilityID())) {
               var3.addElement(var4);
            }
         }
      }

      return var3;
   }

   public ASN1Primitive toASN1Primitive() {
      return this.capabilities;
   }
}
