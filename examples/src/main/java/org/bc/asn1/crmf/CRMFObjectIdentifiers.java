package org.bc.asn1.crmf;

import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;

public interface CRMFObjectIdentifiers {
   ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");
   ASN1ObjectIdentifier id_pkip = id_pkix.branch("5");
   ASN1ObjectIdentifier id_regCtrl = id_pkip.branch("1");
   ASN1ObjectIdentifier id_regCtrl_regToken = id_regCtrl.branch("1");
   ASN1ObjectIdentifier id_regCtrl_authenticator = id_regCtrl.branch("2");
   ASN1ObjectIdentifier id_regCtrl_pkiPublicationInfo = id_regCtrl.branch("3");
   ASN1ObjectIdentifier id_regCtrl_pkiArchiveOptions = id_regCtrl.branch("4");
   ASN1ObjectIdentifier id_ct_encKeyWithID = new ASN1ObjectIdentifier(PKCSObjectIdentifiers.id_ct + ".21");
}
