package org.bc.asn1.cms;

import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;

public interface CMSAttributes {
   ASN1ObjectIdentifier contentType = PKCSObjectIdentifiers.pkcs_9_at_contentType;
   ASN1ObjectIdentifier messageDigest = PKCSObjectIdentifiers.pkcs_9_at_messageDigest;
   ASN1ObjectIdentifier signingTime = PKCSObjectIdentifiers.pkcs_9_at_signingTime;
   ASN1ObjectIdentifier counterSignature = PKCSObjectIdentifiers.pkcs_9_at_counterSignature;
   ASN1ObjectIdentifier contentHint = PKCSObjectIdentifiers.id_aa_contentHint;
}
