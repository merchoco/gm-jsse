package org.bc.asn1.x509.qualified;

import org.bc.asn1.ASN1ObjectIdentifier;

public interface ETSIQCObjectIdentifiers {
   ASN1ObjectIdentifier id_etsi_qcs = new ASN1ObjectIdentifier("0.4.0.1862.1");
   ASN1ObjectIdentifier id_etsi_qcs_QcCompliance = id_etsi_qcs.branch("1");
   ASN1ObjectIdentifier id_etsi_qcs_LimiteValue = id_etsi_qcs.branch("2");
   ASN1ObjectIdentifier id_etsi_qcs_RetentionPeriod = id_etsi_qcs.branch("3");
   ASN1ObjectIdentifier id_etsi_qcs_QcSSCD = id_etsi_qcs.branch("4");
}
