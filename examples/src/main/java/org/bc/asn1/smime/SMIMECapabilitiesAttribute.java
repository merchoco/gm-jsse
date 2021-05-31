package org.bc.asn1.smime;

import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERSet;
import org.bc.asn1.cms.Attribute;

public class SMIMECapabilitiesAttribute extends Attribute {
   public SMIMECapabilitiesAttribute(SMIMECapabilityVector var1) {
      super((ASN1ObjectIdentifier)SMIMEAttributes.smimeCapabilities, new DERSet(new DERSequence(var1.toASN1EncodableVector())));
   }
}
