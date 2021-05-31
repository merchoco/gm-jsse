package org.bc.asn1.x500;

import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1ObjectIdentifier;

public interface X500NameStyle {
   ASN1Encodable stringToValue(ASN1ObjectIdentifier var1, String var2);

   ASN1ObjectIdentifier attrNameToOID(String var1);

   boolean areEqual(X500Name var1, X500Name var2);

   RDN[] fromString(String var1);

   int calculateHashCode(X500Name var1);

   String toString(X500Name var1);
}
