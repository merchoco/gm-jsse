package org.bc.asn1.cms;

import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;

public interface CMSObjectIdentifiers {
   ASN1ObjectIdentifier data = PKCSObjectIdentifiers.data;
   ASN1ObjectIdentifier signedData = PKCSObjectIdentifiers.signedData;
   ASN1ObjectIdentifier envelopedData = PKCSObjectIdentifiers.envelopedData;
   ASN1ObjectIdentifier signedAndEnvelopedData = PKCSObjectIdentifiers.signedAndEnvelopedData;
   ASN1ObjectIdentifier digestedData = PKCSObjectIdentifiers.digestedData;
   ASN1ObjectIdentifier encryptedData = PKCSObjectIdentifiers.encryptedData;
   ASN1ObjectIdentifier authenticatedData = PKCSObjectIdentifiers.id_ct_authData;
   ASN1ObjectIdentifier compressedData = PKCSObjectIdentifiers.id_ct_compressedData;
   ASN1ObjectIdentifier authEnvelopedData = PKCSObjectIdentifiers.id_ct_authEnvelopedData;
   ASN1ObjectIdentifier timestampedData = PKCSObjectIdentifiers.id_ct_timestampedData;
}
