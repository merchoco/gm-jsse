package org.bc.asn1.smime;

import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.DERSet;
import org.bc.asn1.DERTaggedObject;
import org.bc.asn1.cms.Attribute;
import org.bc.asn1.cms.IssuerAndSerialNumber;
import org.bc.asn1.cms.RecipientKeyIdentifier;

public class SMIMEEncryptionKeyPreferenceAttribute extends Attribute {
   public SMIMEEncryptionKeyPreferenceAttribute(IssuerAndSerialNumber var1) {
      super((ASN1ObjectIdentifier)SMIMEAttributes.encrypKeyPref, new DERSet(new DERTaggedObject(false, 0, var1)));
   }

   public SMIMEEncryptionKeyPreferenceAttribute(RecipientKeyIdentifier var1) {
      super((ASN1ObjectIdentifier)SMIMEAttributes.encrypKeyPref, new DERSet(new DERTaggedObject(false, 1, var1)));
   }

   public SMIMEEncryptionKeyPreferenceAttribute(ASN1OctetString var1) {
      super((ASN1ObjectIdentifier)SMIMEAttributes.encrypKeyPref, new DERSet(new DERTaggedObject(false, 2, var1)));
   }
}
