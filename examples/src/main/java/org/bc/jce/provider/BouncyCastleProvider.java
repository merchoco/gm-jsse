package org.bc.jce.provider;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.bc.BCObjectIdentifiers;
import org.bc.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.pkcs.PrivateKeyInfo;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.config.ProviderConfiguration;
import org.bc.jcajce.provider.util.AlgorithmProvider;
import org.bc.jcajce.provider.util.AsymmetricKeyInfoConverter;

public final class BouncyCastleProvider extends Provider implements ConfigurableProvider {
   private static String info = "BouncyCastle Security Provider v1.48";
   public static String PROVIDER_NAME = "BC";
   public static final ProviderConfiguration CONFIGURATION = new BouncyCastleProviderConfiguration();
   private static final Map keyInfoConverters = new HashMap();
   private static final String SYMMETRIC_CIPHER_PACKAGE = "org.bc.jcajce.provider.symmetric.";
   private static final String[] SYMMETRIC_CIPHERS = new String[]{"AES", "ARC4", "Blowfish", "Camellia", "CAST5", "CAST6", "DES", "DESede", "GOST28147", "Grainv1", "Grain128", "HC128", "HC256", "IDEA", "Noekeon", "RC2", "RC5", "RC6", "Rijndael", "Salsa20", "SEED", "Serpent", "Skipjack", "TEA", "Twofish", "VMPC", "VMPCKSA3", "XTEA"};
   private static final String ASYMMETRIC_CIPHER_PACKAGE = "org.bc.jcajce.provider.asymmetric.";
   private static final String[] ASYMMETRIC_GENERIC = new String[]{"X509"};
   private static final String[] ASYMMETRIC_CIPHERS = new String[]{"DSA", "DH", "EC", "RSA", "GOST", "ECGOST", "ElGamal", "DSTU4145"};
   private static final String DIGEST_PACKAGE = "org.bc.jcajce.provider.digest.";
   private static final String[] DIGESTS = new String[]{"GOST3411", "MD2", "MD4", "MD5", "SHA1", "RIPEMD128", "RIPEMD160", "RIPEMD256", "RIPEMD320", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3", "Tiger", "Whirlpool"};

   public BouncyCastleProvider() {
      super(PROVIDER_NAME, 1.48D, info);
      AccessController.doPrivileged(new PrivilegedAction() {
         public Object run() {
            BouncyCastleProvider.this.setup();
            return null;
         }
      });
   }

   private void setup() {
      this.loadAlgorithms("org.bc.jcajce.provider.digest.", DIGESTS);
      this.loadAlgorithms("org.bc.jcajce.provider.symmetric.", SYMMETRIC_CIPHERS);
      this.loadAlgorithms("org.bc.jcajce.provider.asymmetric.", ASYMMETRIC_GENERIC);
      this.loadAlgorithms("org.bc.jcajce.provider.asymmetric.", ASYMMETRIC_CIPHERS);
      this.put("X509Store.CERTIFICATE/COLLECTION", "org.bc.jce.provider.X509StoreCertCollection");
      this.put("X509Store.ATTRIBUTECERTIFICATE/COLLECTION", "org.bc.jce.provider.X509StoreAttrCertCollection");
      this.put("X509Store.CRL/COLLECTION", "org.bc.jce.provider.X509StoreCRLCollection");
      this.put("X509Store.CERTIFICATEPAIR/COLLECTION", "org.bc.jce.provider.X509StoreCertPairCollection");
      this.put("X509Store.CERTIFICATE/LDAP", "org.bc.jce.provider.X509StoreLDAPCerts");
      this.put("X509Store.CRL/LDAP", "org.bc.jce.provider.X509StoreLDAPCRLs");
      this.put("X509Store.ATTRIBUTECERTIFICATE/LDAP", "org.bc.jce.provider.X509StoreLDAPAttrCerts");
      this.put("X509Store.CERTIFICATEPAIR/LDAP", "org.bc.jce.provider.X509StoreLDAPCertPairs");
      this.put("X509StreamParser.CERTIFICATE", "org.bc.jce.provider.X509CertParser");
      this.put("X509StreamParser.ATTRIBUTECERTIFICATE", "org.bc.jce.provider.X509AttrCertParser");
      this.put("X509StreamParser.CRL", "org.bc.jce.provider.X509CRLParser");
      this.put("X509StreamParser.CERTIFICATEPAIR", "org.bc.jce.provider.X509CertPairParser");
      this.put("KeyStore.BKS", "org.bc.jce.provider.JDKKeyStore");
      this.put("KeyStore.BouncyCastle", "org.bc.jce.provider.JDKKeyStore$BouncyCastleStore");
      this.put("KeyStore.PKCS12", "org.bc.jce.provider.JDKPKCS12KeyStore$BCPKCS12KeyStore");
      this.put("KeyStore.BCPKCS12", "org.bc.jce.provider.JDKPKCS12KeyStore$BCPKCS12KeyStore");
      this.put("KeyStore.PKCS12-DEF", "org.bc.jce.provider.JDKPKCS12KeyStore$DefPKCS12KeyStore");
      this.put("KeyStore.PKCS12-3DES-40RC2", "org.bc.jce.provider.JDKPKCS12KeyStore$BCPKCS12KeyStore");
      this.put("KeyStore.PKCS12-3DES-3DES", "org.bc.jce.provider.JDKPKCS12KeyStore$BCPKCS12KeyStore3DES");
      this.put("KeyStore.PKCS12-DEF-3DES-40RC2", "org.bc.jce.provider.JDKPKCS12KeyStore$DefPKCS12KeyStore");
      this.put("KeyStore.PKCS12-DEF-3DES-3DES", "org.bc.jce.provider.JDKPKCS12KeyStore$DefPKCS12KeyStore3DES");
      this.put("Alg.Alias.KeyStore.UBER", "BouncyCastle");
      this.put("Alg.Alias.KeyStore.BOUNCYCASTLE", "BouncyCastle");
      this.put("Alg.Alias.KeyStore.bouncycastle", "BouncyCastle");
      this.put("AlgorithmParameters.IES", "org.bc.jce.provider.JDKAlgorithmParameters$IES");
      this.put("AlgorithmParameters.PKCS12PBE", "org.bc.jce.provider.JDKAlgorithmParameters$PKCS12PBE");
      this.put("AlgorithmParameters." + PKCSObjectIdentifiers.id_PBKDF2, "org.bc.jce.provider.JDKAlgorithmParameters$PBKDF2");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA1ANDRC2", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND3-KEYTRIPLEDES", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND2-KEYTRIPLEDES", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDRC2", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDRC4", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDTWOFISH", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA1ANDRC2-CBC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND3-KEYTRIPLEDES-CBC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND2-KEYTRIPLEDES-CBC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDDES3KEY-CBC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDDES2KEY-CBC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND40BITRC2-CBC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND40BITRC4", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND128BITRC2-CBC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND128BITRC4", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDTWOFISH", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDTWOFISH-CBC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.1", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.2", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.3", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.4", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.5", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.6", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWithSHAAnd3KeyTripleDES", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes128_cbc.getId(), "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes192_cbc.getId(), "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes256_cbc.getId(), "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes128_cbc.getId(), "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes192_cbc.getId(), "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes256_cbc.getId(), "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND128BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND192BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND256BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA256AND128BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA256AND192BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA256AND256BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA1AND128BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA1AND192BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA1AND256BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA-1AND128BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA-1AND192BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA-1AND256BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA-256AND128BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA-256AND192BITAES-CBC-BC", "PKCS12PBE");
      this.put("Alg.Alias.AlgorithmParameters.PBEWITHSHA-256AND256BITAES-CBC-BC", "PKCS12PBE");
      this.put("AlgorithmParameters.SHA1WITHECDSA", "org.bc.jce.provider.JDKECDSAAlgParameters$SigAlgParameters");
      this.put("AlgorithmParameters.SHA224WITHECDSA", "org.bc.jce.provider.JDKECDSAAlgParameters$SigAlgParameters");
      this.put("AlgorithmParameters.SHA256WITHECDSA", "org.bc.jce.provider.JDKECDSAAlgParameters$SigAlgParameters");
      this.put("AlgorithmParameters.SHA384WITHECDSA", "org.bc.jce.provider.JDKECDSAAlgParameters$SigAlgParameters");
      this.put("AlgorithmParameters.SHA512WITHECDSA", "org.bc.jce.provider.JDKECDSAAlgParameters$SigAlgParameters");
      this.put("Alg.Alias.Cipher.PBEWithSHAAnd3KeyTripleDES", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
      this.put("Cipher.IES", "org.bc.jce.provider.JCEIESCipher$IES");
      this.put("Cipher.BrokenIES", "org.bc.jce.provider.JCEIESCipher$BrokenIES");
      this.put("Cipher.PBEWITHMD5ANDDES", "org.bc.jce.provider.JCEBlockCipher$PBEWithMD5AndDES");
      this.put("Cipher.BROKENPBEWITHMD5ANDDES", "org.bc.jce.provider.BrokenJCEBlockCipher$BrokePBEWithMD5AndDES");
      this.put("Cipher.PBEWITHMD5ANDRC2", "org.bc.jce.provider.JCEBlockCipher$PBEWithMD5AndRC2");
      this.put("Cipher.PBEWITHSHA1ANDDES", "org.bc.jce.provider.JCEBlockCipher$PBEWithSHA1AndDES");
      this.put("Cipher.BROKENPBEWITHSHA1ANDDES", "org.bc.jce.provider.BrokenJCEBlockCipher$BrokePBEWithSHA1AndDES");
      this.put("Cipher.PBEWITHSHA1ANDRC2", "org.bc.jce.provider.JCEBlockCipher$PBEWithSHA1AndRC2");
      this.put("Cipher.PBEWITHSHAAND128BITRC2-CBC", "org.bc.jce.provider.JCEBlockCipher$PBEWithSHAAnd128BitRC2");
      this.put("Cipher.PBEWITHSHAAND40BITRC2-CBC", "org.bc.jce.provider.JCEBlockCipher$PBEWithSHAAnd40BitRC2");
      this.put("Cipher.PBEWITHSHAAND128BITRC4", "org.bc.jce.provider.JCEStreamCipher$PBEWithSHAAnd128BitRC4");
      this.put("Cipher.PBEWITHSHAAND40BITRC4", "org.bc.jce.provider.JCEStreamCipher$PBEWithSHAAnd40BitRC4");
      this.put("Alg.Alias.Cipher.PBEWITHSHA1AND128BITRC2-CBC", "PBEWITHSHAAND128BITRC2-CBC");
      this.put("Alg.Alias.Cipher.PBEWITHSHA1AND40BITRC2-CBC", "PBEWITHSHAAND40BITRC2-CBC");
      this.put("Alg.Alias.Cipher.PBEWITHSHA1AND128BITRC4", "PBEWITHSHAAND128BITRC4");
      this.put("Alg.Alias.Cipher.PBEWITHSHA1AND40BITRC4", "PBEWITHSHAAND40BITRC4");
      this.put("Alg.Alias.Cipher." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes128_cbc.getId(), "PBEWITHSHAAND128BITAES-CBC-BC");
      this.put("Alg.Alias.Cipher." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes192_cbc.getId(), "PBEWITHSHAAND192BITAES-CBC-BC");
      this.put("Alg.Alias.Cipher." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes256_cbc.getId(), "PBEWITHSHAAND256BITAES-CBC-BC");
      this.put("Alg.Alias.Cipher." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes128_cbc.getId(), "PBEWITHSHA256AND128BITAES-CBC-BC");
      this.put("Alg.Alias.Cipher." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes192_cbc.getId(), "PBEWITHSHA256AND192BITAES-CBC-BC");
      this.put("Alg.Alias.Cipher." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes256_cbc.getId(), "PBEWITHSHA256AND256BITAES-CBC-BC");
      this.put("Cipher.PBEWITHSHAAND128BITAES-CBC-BC", "org.bc.jce.provider.JCEBlockCipher$PBEWithAESCBC");
      this.put("Cipher.PBEWITHSHAAND192BITAES-CBC-BC", "org.bc.jce.provider.JCEBlockCipher$PBEWithAESCBC");
      this.put("Cipher.PBEWITHSHAAND256BITAES-CBC-BC", "org.bc.jce.provider.JCEBlockCipher$PBEWithAESCBC");
      this.put("Cipher.PBEWITHSHA256AND128BITAES-CBC-BC", "org.bc.jce.provider.JCEBlockCipher$PBEWithAESCBC");
      this.put("Cipher.PBEWITHSHA256AND192BITAES-CBC-BC", "org.bc.jce.provider.JCEBlockCipher$PBEWithAESCBC");
      this.put("Cipher.PBEWITHSHA256AND256BITAES-CBC-BC", "org.bc.jce.provider.JCEBlockCipher$PBEWithAESCBC");
      this.put("Alg.Alias.Cipher.PBEWITHSHA1AND128BITAES-CBC-BC", "PBEWITHSHAAND128BITAES-CBC-BC");
      this.put("Alg.Alias.Cipher.PBEWITHSHA1AND192BITAES-CBC-BC", "PBEWITHSHAAND192BITAES-CBC-BC");
      this.put("Alg.Alias.Cipher.PBEWITHSHA1AND256BITAES-CBC-BC", "PBEWITHSHAAND256BITAES-CBC-BC");
      this.put("Alg.Alias.Cipher.PBEWITHSHA-1AND128BITAES-CBC-BC", "PBEWITHSHAAND128BITAES-CBC-BC");
      this.put("Alg.Alias.Cipher.PBEWITHSHA-1AND192BITAES-CBC-BC", "PBEWITHSHAAND192BITAES-CBC-BC");
      this.put("Alg.Alias.Cipher.PBEWITHSHA-1AND256BITAES-CBC-BC", "PBEWITHSHAAND256BITAES-CBC-BC");
      this.put("Alg.Alias.Cipher.PBEWITHSHA-256AND128BITAES-CBC-BC", "PBEWITHSHA256AND128BITAES-CBC-BC");
      this.put("Alg.Alias.Cipher.PBEWITHSHA-256AND192BITAES-CBC-BC", "PBEWITHSHA256AND192BITAES-CBC-BC");
      this.put("Alg.Alias.Cipher.PBEWITHSHA-256AND256BITAES-CBC-BC", "PBEWITHSHA256AND256BITAES-CBC-BC");
      this.put("Cipher.PBEWITHMD5AND128BITAES-CBC-OPENSSL", "org.bc.jce.provider.JCEBlockCipher$PBEWithAESCBC");
      this.put("Cipher.PBEWITHMD5AND192BITAES-CBC-OPENSSL", "org.bc.jce.provider.JCEBlockCipher$PBEWithAESCBC");
      this.put("Cipher.PBEWITHMD5AND256BITAES-CBC-OPENSSL", "org.bc.jce.provider.JCEBlockCipher$PBEWithAESCBC");
      this.put("Cipher.PBEWITHSHAANDTWOFISH-CBC", "org.bc.jce.provider.JCEBlockCipher$PBEWithSHAAndTwofish");
      this.put("Cipher.OLDPBEWITHSHAANDTWOFISH-CBC", "org.bc.jce.provider.BrokenJCEBlockCipher$OldPBEWithSHAAndTwofish");
      this.put("Alg.Alias.Cipher." + PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC, "PBEWITHMD2ANDDES");
      this.put("Alg.Alias.Cipher." + PKCSObjectIdentifiers.pbeWithMD2AndRC2_CBC, "PBEWITHMD2ANDRC2");
      this.put("Alg.Alias.Cipher." + PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC, "PBEWITHMD5ANDDES");
      this.put("Alg.Alias.Cipher." + PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC, "PBEWITHMD5ANDDES");
      this.put("Alg.Alias.Cipher." + PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC, "PBEWITHSHA1ANDDES");
      this.put("Alg.Alias.Cipher." + PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC, "PBEWITHSHA1ANDRC2");
      this.put("Alg.Alias.Cipher.1.2.840.113549.1.12.1.1", "PBEWITHSHAAND128BITRC4");
      this.put("Alg.Alias.Cipher.1.2.840.113549.1.12.1.2", "PBEWITHSHAAND40BITRC4");
      this.put("Alg.Alias.Cipher.1.2.840.113549.1.12.1.5", "PBEWITHSHAAND128BITRC2-CBC");
      this.put("Alg.Alias.Cipher.1.2.840.113549.1.12.1.6", "PBEWITHSHAAND40BITRC2-CBC");
      this.put("SecretKeyFactory.PBEWITHMD2ANDDES", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithMD2AndDES");
      this.put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC, "PBEWITHMD2ANDDES");
      this.put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD2AndRC2_CBC, "PBEWITHMD2ANDRC2");
      this.put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC, "PBEWITHMD5ANDDES");
      this.put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC, "PBEWITHMD5ANDDES");
      this.put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC, "PBEWITHSHA1ANDDES");
      this.put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC, "PBEWITHSHA1ANDRC2");
      this.put("SecretKeyFactory.PBEWITHMD2ANDRC2", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithMD2AndRC2");
      this.put("SecretKeyFactory.PBEWITHMD5ANDDES", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithMD5AndDES");
      this.put("SecretKeyFactory.PBEWITHMD5ANDRC2", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithMD5AndRC2");
      this.put("SecretKeyFactory.PBEWITHSHA1ANDDES", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHA1AndDES");
      this.put("SecretKeyFactory.PBEWITHSHA1ANDRC2", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHA1AndRC2");
      this.put("SecretKeyFactory.PBEWITHSHAAND3-KEYTRIPLEDES-CBC", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHAAndDES3Key");
      this.put("SecretKeyFactory.PBEWITHSHAAND2-KEYTRIPLEDES-CBC", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHAAndDES2Key");
      this.put("SecretKeyFactory.PBEWITHSHAAND128BITRC4", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHAAnd128BitRC4");
      this.put("SecretKeyFactory.PBEWITHSHAAND40BITRC4", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHAAnd40BitRC4");
      this.put("SecretKeyFactory.PBEWITHSHAAND128BITRC2-CBC", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHAAnd128BitRC2");
      this.put("SecretKeyFactory.PBEWITHSHAAND40BITRC2-CBC", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHAAnd40BitRC2");
      this.put("SecretKeyFactory.PBEWITHSHAANDTWOFISH-CBC", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHAAndTwofish");
      this.put("SecretKeyFactory.PBEWITHHMACRIPEMD160", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithRIPEMD160");
      this.put("SecretKeyFactory.PBEWITHHMACSHA1", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHA");
      this.put("SecretKeyFactory.PBEWITHHMACTIGER", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithTiger");
      this.put("SecretKeyFactory.PBEWITHMD5AND128BITAES-CBC-OPENSSL", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithMD5And128BitAESCBCOpenSSL");
      this.put("SecretKeyFactory.PBEWITHMD5AND192BITAES-CBC-OPENSSL", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithMD5And192BitAESCBCOpenSSL");
      this.put("SecretKeyFactory.PBEWITHMD5AND256BITAES-CBC-OPENSSL", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithMD5And256BitAESCBCOpenSSL");
      this.put("SecretKeyFactory." + CryptoProObjectIdentifiers.gostR3411, "org.bc.jce.provider.JCESecretKeyFactory$PBEWithGOST3411");
      this.put("Alg.Alias.SecretKeyFactory.PBE", "PBE/PKCS5");
      this.put("Alg.Alias.SecretKeyFactory.BROKENPBEWITHMD5ANDDES", "PBE/PKCS5");
      this.put("Alg.Alias.SecretKeyFactory.BROKENPBEWITHSHA1ANDDES", "PBE/PKCS5");
      this.put("Alg.Alias.SecretKeyFactory.OLDPBEWITHSHAAND3-KEYTRIPLEDES-CBC", "PBE/PKCS12");
      this.put("Alg.Alias.SecretKeyFactory.BROKENPBEWITHSHAAND3-KEYTRIPLEDES-CBC", "PBE/PKCS12");
      this.put("Alg.Alias.SecretKeyFactory.BROKENPBEWITHSHAAND2-KEYTRIPLEDES-CBC", "PBE/PKCS12");
      this.put("Alg.Alias.SecretKeyFactory.OLDPBEWITHSHAANDTWOFISH-CBC", "PBE/PKCS12");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHMD2ANDDES-CBC", "PBEWITHMD2ANDDES");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHMD2ANDRC2-CBC", "PBEWITHMD2ANDRC2");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHMD5ANDDES-CBC", "PBEWITHMD5ANDDES");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHMD5ANDRC2-CBC", "PBEWITHMD5ANDRC2");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHSHA1ANDDES-CBC", "PBEWITHSHA1ANDDES");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHSHA1ANDRC2-CBC", "PBEWITHSHA1ANDRC2");
      this.put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC, "PBEWITHMD2ANDDES");
      this.put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD2AndRC2_CBC, "PBEWITHMD2ANDRC2");
      this.put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC, "PBEWITHMD5ANDDES");
      this.put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC, "PBEWITHMD5ANDRC2");
      this.put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC, "PBEWITHSHA1ANDDES");
      this.put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC, "PBEWITHSHA1ANDRC2");
      this.put("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.1", "PBEWITHSHAAND128BITRC4");
      this.put("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.2", "PBEWITHSHAAND40BITRC4");
      this.put("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.3", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
      this.put("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.4", "PBEWITHSHAAND2-KEYTRIPLEDES-CBC");
      this.put("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.5", "PBEWITHSHAAND128BITRC2-CBC");
      this.put("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.6", "PBEWITHSHAAND40BITRC2-CBC");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHHMACSHA", "PBEWITHHMACSHA1");
      this.put("Alg.Alias.SecretKeyFactory.1.3.14.3.2.26", "PBEWITHHMACSHA1");
      this.put("Alg.Alias.SecretKeyFactory.PBEWithSHAAnd3KeyTripleDES", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
      this.put("SecretKeyFactory.PBEWITHSHAAND128BITAES-CBC-BC", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHAAnd128BitAESBC");
      this.put("SecretKeyFactory.PBEWITHSHAAND192BITAES-CBC-BC", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHAAnd192BitAESBC");
      this.put("SecretKeyFactory.PBEWITHSHAAND256BITAES-CBC-BC", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHAAnd256BitAESBC");
      this.put("SecretKeyFactory.PBEWITHSHA256AND128BITAES-CBC-BC", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHA256And128BitAESBC");
      this.put("SecretKeyFactory.PBEWITHSHA256AND192BITAES-CBC-BC", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHA256And192BitAESBC");
      this.put("SecretKeyFactory.PBEWITHSHA256AND256BITAES-CBC-BC", "org.bc.jce.provider.JCESecretKeyFactory$PBEWithSHA256And256BitAESBC");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHSHA1AND128BITAES-CBC-BC", "PBEWITHSHAAND128BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHSHA1AND192BITAES-CBC-BC", "PBEWITHSHAAND192BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHSHA1AND256BITAES-CBC-BC", "PBEWITHSHAAND256BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHSHA-1AND128BITAES-CBC-BC", "PBEWITHSHAAND128BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHSHA-1AND192BITAES-CBC-BC", "PBEWITHSHAAND192BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHSHA-1AND256BITAES-CBC-BC", "PBEWITHSHAAND256BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND128BITAES-CBC-BC", "PBEWITHSHA256AND128BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND192BITAES-CBC-BC", "PBEWITHSHA256AND192BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND256BITAES-CBC-BC", "PBEWITHSHA256AND256BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes128_cbc.getId(), "PBEWITHSHAAND128BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes192_cbc.getId(), "PBEWITHSHAAND192BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes256_cbc.getId(), "PBEWITHSHAAND256BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes128_cbc.getId(), "PBEWITHSHA256AND128BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes192_cbc.getId(), "PBEWITHSHA256AND192BITAES-CBC-BC");
      this.put("Alg.Alias.SecretKeyFactory." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes256_cbc.getId(), "PBEWITHSHA256AND256BITAES-CBC-BC");
      this.addMacAlgorithms();
      this.put("CertPathValidator.RFC3281", "org.bc.jce.provider.PKIXAttrCertPathValidatorSpi");
      this.put("CertPathBuilder.RFC3281", "org.bc.jce.provider.PKIXAttrCertPathBuilderSpi");
      this.put("CertPathValidator.RFC3280", "org.bc.jce.provider.PKIXCertPathValidatorSpi");
      this.put("CertPathBuilder.RFC3280", "org.bc.jce.provider.PKIXCertPathBuilderSpi");
      this.put("CertPathValidator.PKIX", "org.bc.jce.provider.PKIXCertPathValidatorSpi");
      this.put("CertPathBuilder.PKIX", "org.bc.jce.provider.PKIXCertPathBuilderSpi");
      this.put("CertStore.Collection", "org.bc.jce.provider.CertStoreCollectionSpi");
      this.put("CertStore.LDAP", "org.bc.jce.provider.X509LDAPCertStoreSpi");
      this.put("CertStore.Multi", "org.bc.jce.provider.MultiCertStoreSpi");
      this.put("Alg.Alias.CertStore.X509LDAP", "LDAP");
   }

   private void loadAlgorithms(String var1, String[] var2) {
      for(int var3 = 0; var3 != var2.length; ++var3) {
         Class var4 = null;

         try {
            ClassLoader var5 = this.getClass().getClassLoader();
            if (var5 != null) {
               var4 = var5.loadClass(var1 + var2[var3] + "$Mappings");
            } else {
               var4 = Class.forName(var1 + var2[var3] + "$Mappings");
            }
         } catch (ClassNotFoundException var7) {
            ;
         }

         if (var4 != null) {
            try {
               ((AlgorithmProvider)var4.newInstance()).configure(this);
            } catch (Exception var6) {
               throw new InternalError("cannot create instance of " + var1 + var2[var3] + "$Mappings : " + var6);
            }
         }
      }

   }

   private void addMacAlgorithms() {
      this.put("Mac.DESWITHISO9797", "org.bc.jce.provider.JCEMac$DES9797Alg3");
      this.put("Alg.Alias.Mac.DESISO9797MAC", "DESWITHISO9797");
      this.put("Mac.ISO9797ALG3MAC", "org.bc.jce.provider.JCEMac$DES9797Alg3");
      this.put("Alg.Alias.Mac.ISO9797ALG3", "ISO9797ALG3MAC");
      this.put("Mac.ISO9797ALG3WITHISO7816-4PADDING", "org.bc.jce.provider.JCEMac$DES9797Alg3with7816d4");
      this.put("Alg.Alias.Mac.ISO9797ALG3MACWITHISO7816-4PADDING", "ISO9797ALG3WITHISO7816-4PADDING");
      this.put("Mac.OLDHMACSHA384", "org.bc.jce.provider.JCEMac$OldSHA384");
      this.put("Mac.OLDHMACSHA512", "org.bc.jce.provider.JCEMac$OldSHA512");
      this.put("Mac.PBEWITHHMACSHA", "org.bc.jce.provider.JCEMac$PBEWithSHA");
      this.put("Mac.PBEWITHHMACSHA1", "org.bc.jce.provider.JCEMac$PBEWithSHA");
      this.put("Mac.PBEWITHHMACRIPEMD160", "org.bc.jce.provider.JCEMac$PBEWithRIPEMD160");
      this.put("Alg.Alias.Mac.1.3.14.3.2.26", "PBEWITHHMACSHA");
   }

   public void setParameter(String var1, Object var2) {
      ProviderConfiguration var3 = CONFIGURATION;
      synchronized(CONFIGURATION) {
         ((BouncyCastleProviderConfiguration)CONFIGURATION).setParameter(var1, var2);
      }
   }

   public boolean hasAlgorithm(String var1, String var2) {
      return this.containsKey(var1 + "." + var2) || this.containsKey("Alg.Alias." + var1 + "." + var2);
   }

   public void addAlgorithm(String var1, String var2) {
      if (this.containsKey(var1)) {
         throw new IllegalStateException("duplicate provider key (" + var1 + ") found");
      } else {
         this.put(var1, var2);
      }
   }

   public void addKeyInfoConverter(ASN1ObjectIdentifier var1, AsymmetricKeyInfoConverter var2) {
      keyInfoConverters.put(var1, var2);
   }

   public static PublicKey getPublicKey(SubjectPublicKeyInfo var0) throws IOException {
      AsymmetricKeyInfoConverter var1 = (AsymmetricKeyInfoConverter)keyInfoConverters.get(var0.getAlgorithm().getAlgorithm());
      return var1 == null ? null : var1.generatePublic(var0);
   }

   public static PrivateKey getPrivateKey(PrivateKeyInfo var0) throws IOException {
      AsymmetricKeyInfoConverter var1 = (AsymmetricKeyInfoConverter)keyInfoConverters.get(var0.getPrivateKeyAlgorithm().getAlgorithm());
      return var1 == null ? null : var1.generatePrivate(var0);
   }
}
