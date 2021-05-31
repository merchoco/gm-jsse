package org.bc.asn1.misc;

import org.bc.asn1.ASN1ObjectIdentifier;

public interface MiscObjectIdentifiers {
   ASN1ObjectIdentifier netscape = new ASN1ObjectIdentifier("2.16.840.1.113730.1");
   ASN1ObjectIdentifier netscapeCertType = netscape.branch("1");
   ASN1ObjectIdentifier netscapeBaseURL = netscape.branch("2");
   ASN1ObjectIdentifier netscapeRevocationURL = netscape.branch("3");
   ASN1ObjectIdentifier netscapeCARevocationURL = netscape.branch("4");
   ASN1ObjectIdentifier netscapeRenewalURL = netscape.branch("7");
   ASN1ObjectIdentifier netscapeCApolicyURL = netscape.branch("8");
   ASN1ObjectIdentifier netscapeSSLServerName = netscape.branch("12");
   ASN1ObjectIdentifier netscapeCertComment = netscape.branch("13");
   ASN1ObjectIdentifier verisign = new ASN1ObjectIdentifier("2.16.840.1.113733.1");
   ASN1ObjectIdentifier verisignCzagExtension = verisign.branch("6.3");
   ASN1ObjectIdentifier verisignDnbDunsNumber = verisign.branch("6.15");
   ASN1ObjectIdentifier novell = new ASN1ObjectIdentifier("2.16.840.1.113719");
   ASN1ObjectIdentifier novellSecurityAttribs = novell.branch("1.9.4.1");
   ASN1ObjectIdentifier entrust = new ASN1ObjectIdentifier("1.2.840.113533.7");
   ASN1ObjectIdentifier entrustVersionExtension = entrust.branch("65.0");
}
