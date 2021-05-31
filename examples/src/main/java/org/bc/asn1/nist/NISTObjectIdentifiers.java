package org.bc.asn1.nist;

import org.bc.asn1.ASN1ObjectIdentifier;

public interface NISTObjectIdentifiers {
   ASN1ObjectIdentifier nistAlgorithm = new ASN1ObjectIdentifier("2.16.840.1.101.3.4");
   ASN1ObjectIdentifier id_sha256 = nistAlgorithm.branch("2.1");
   ASN1ObjectIdentifier id_sha384 = nistAlgorithm.branch("2.2");
   ASN1ObjectIdentifier id_sha512 = nistAlgorithm.branch("2.3");
   ASN1ObjectIdentifier id_sha224 = nistAlgorithm.branch("2.4");
   ASN1ObjectIdentifier aes = nistAlgorithm.branch("1");
   ASN1ObjectIdentifier id_aes128_ECB = aes.branch("1");
   ASN1ObjectIdentifier id_aes128_CBC = aes.branch("2");
   ASN1ObjectIdentifier id_aes128_OFB = aes.branch("3");
   ASN1ObjectIdentifier id_aes128_CFB = aes.branch("4");
   ASN1ObjectIdentifier id_aes128_wrap = aes.branch("5");
   ASN1ObjectIdentifier id_aes128_GCM = aes.branch("6");
   ASN1ObjectIdentifier id_aes128_CCM = aes.branch("7");
   ASN1ObjectIdentifier id_aes192_ECB = aes.branch("21");
   ASN1ObjectIdentifier id_aes192_CBC = aes.branch("22");
   ASN1ObjectIdentifier id_aes192_OFB = aes.branch("23");
   ASN1ObjectIdentifier id_aes192_CFB = aes.branch("24");
   ASN1ObjectIdentifier id_aes192_wrap = aes.branch("25");
   ASN1ObjectIdentifier id_aes192_GCM = aes.branch("26");
   ASN1ObjectIdentifier id_aes192_CCM = aes.branch("27");
   ASN1ObjectIdentifier id_aes256_ECB = aes.branch("41");
   ASN1ObjectIdentifier id_aes256_CBC = aes.branch("42");
   ASN1ObjectIdentifier id_aes256_OFB = aes.branch("43");
   ASN1ObjectIdentifier id_aes256_CFB = aes.branch("44");
   ASN1ObjectIdentifier id_aes256_wrap = aes.branch("45");
   ASN1ObjectIdentifier id_aes256_GCM = aes.branch("46");
   ASN1ObjectIdentifier id_aes256_CCM = aes.branch("47");
   ASN1ObjectIdentifier id_dsa_with_sha2 = nistAlgorithm.branch("3");
   ASN1ObjectIdentifier dsa_with_sha224 = id_dsa_with_sha2.branch("1");
   ASN1ObjectIdentifier dsa_with_sha256 = id_dsa_with_sha2.branch("2");
   ASN1ObjectIdentifier dsa_with_sha384 = id_dsa_with_sha2.branch("3");
   ASN1ObjectIdentifier dsa_with_sha512 = id_dsa_with_sha2.branch("4");
}
