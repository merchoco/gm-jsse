package org.bc.asn1.sec;

import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.x9.X9ObjectIdentifiers;

public interface SECObjectIdentifiers {
   ASN1ObjectIdentifier ellipticCurve = new ASN1ObjectIdentifier("1.3.132.0");
   ASN1ObjectIdentifier sect163k1 = ellipticCurve.branch("1");
   ASN1ObjectIdentifier sect163r1 = ellipticCurve.branch("2");
   ASN1ObjectIdentifier sect239k1 = ellipticCurve.branch("3");
   ASN1ObjectIdentifier sect113r1 = ellipticCurve.branch("4");
   ASN1ObjectIdentifier sect113r2 = ellipticCurve.branch("5");
   ASN1ObjectIdentifier secp112r1 = ellipticCurve.branch("6");
   ASN1ObjectIdentifier secp112r2 = ellipticCurve.branch("7");
   ASN1ObjectIdentifier secp160r1 = ellipticCurve.branch("8");
   ASN1ObjectIdentifier secp160k1 = ellipticCurve.branch("9");
   ASN1ObjectIdentifier secp256k1 = ellipticCurve.branch("10");
   ASN1ObjectIdentifier sect163r2 = ellipticCurve.branch("15");
   ASN1ObjectIdentifier sect283k1 = ellipticCurve.branch("16");
   ASN1ObjectIdentifier sect283r1 = ellipticCurve.branch("17");
   ASN1ObjectIdentifier sect131r1 = ellipticCurve.branch("22");
   ASN1ObjectIdentifier sect131r2 = ellipticCurve.branch("23");
   ASN1ObjectIdentifier sect193r1 = ellipticCurve.branch("24");
   ASN1ObjectIdentifier sect193r2 = ellipticCurve.branch("25");
   ASN1ObjectIdentifier sect233k1 = ellipticCurve.branch("26");
   ASN1ObjectIdentifier sect233r1 = ellipticCurve.branch("27");
   ASN1ObjectIdentifier secp128r1 = ellipticCurve.branch("28");
   ASN1ObjectIdentifier secp128r2 = ellipticCurve.branch("29");
   ASN1ObjectIdentifier secp160r2 = ellipticCurve.branch("30");
   ASN1ObjectIdentifier secp192k1 = ellipticCurve.branch("31");
   ASN1ObjectIdentifier secp224k1 = ellipticCurve.branch("32");
   ASN1ObjectIdentifier secp224r1 = ellipticCurve.branch("33");
   ASN1ObjectIdentifier secp384r1 = ellipticCurve.branch("34");
   ASN1ObjectIdentifier secp521r1 = ellipticCurve.branch("35");
   ASN1ObjectIdentifier sect409k1 = ellipticCurve.branch("36");
   ASN1ObjectIdentifier sect409r1 = ellipticCurve.branch("37");
   ASN1ObjectIdentifier sect571k1 = ellipticCurve.branch("38");
   ASN1ObjectIdentifier sect571r1 = ellipticCurve.branch("39");
   ASN1ObjectIdentifier secp192r1 = X9ObjectIdentifiers.prime192v1;
   ASN1ObjectIdentifier secp256r1 = X9ObjectIdentifiers.prime256v1;
}
