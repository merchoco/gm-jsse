package org.bc.asn1.iana;

import org.bc.asn1.ASN1ObjectIdentifier;

public interface IANAObjectIdentifiers {
   ASN1ObjectIdentifier isakmpOakley = new ASN1ObjectIdentifier("1.3.6.1.5.5.8.1");
   ASN1ObjectIdentifier hmacMD5 = new ASN1ObjectIdentifier(isakmpOakley + ".1");
   ASN1ObjectIdentifier hmacSHA1 = new ASN1ObjectIdentifier(isakmpOakley + ".2");
   ASN1ObjectIdentifier hmacTIGER = new ASN1ObjectIdentifier(isakmpOakley + ".3");
   ASN1ObjectIdentifier hmacRIPEMD160 = new ASN1ObjectIdentifier(isakmpOakley + ".4");
}
