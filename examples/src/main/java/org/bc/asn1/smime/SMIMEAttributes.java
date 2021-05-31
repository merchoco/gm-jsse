package org.bc.asn1.smime;

import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;

public interface SMIMEAttributes {
   ASN1ObjectIdentifier smimeCapabilities = PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities;
   ASN1ObjectIdentifier encrypKeyPref = PKCSObjectIdentifiers.id_aa_encrypKeyPref;
}
