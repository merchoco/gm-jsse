package com.aliyun.gmsse;

import sun.security.util.Debug;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Map.Entry;

/**
 * An implementation of X509KeyManager backed by a KeyStore.
 * <p>
 * The backing KeyStore is inspected when this object is constructed.
 * All key entries containing a PrivateKey and a non-empty chain of
 * X509Certificate are then copied into an internal store. This means
 * that subsequent modifications of the KeyStore have no effect on the
 * X509KeyManagerImpl object.
 * <p>
 * Note that this class assumes that all keys are protected by the same
 * password.
 * <p>
 * The JSSE handshake code currently calls into this class via
 * chooseClientAlias() and chooseServerAlias() to find the certificates to
 * use. As implemented here, both always return the first alias returned by
 * getClientAliases() and getServerAliases(). In turn, these methods are
 * implemented by calling getAliases(), which performs the actual lookup.
 * <p>
 * Note that this class currently implements no checking of the local
 * certificates. In particular, it is *not* guaranteed that:
 * . the certificates are within their validity period and not revoked
 * . the signatures verify
 * . they form a PKIX compliant chain.
 * . the certificate extensions allow the certificate to be used for
 * the desired purpose.
 * <p>
 * Chains that fail any of these criteria will probably be rejected by
 * the remote peer.
 */
public final class SunX509KeyManagerImpl extends X509ExtendedKeyManager {
    private static final Debug debug = Debug.getInstance("ssl");
    private static final String[] STRING0 = new String[0];
    private Map<String, SunX509KeyManagerImpl.X509Credentials> credentialsMap = new HashMap();
    private Map<String, String[]> serverAliasCache = new HashMap();

    private String type;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public SunX509KeyManagerImpl() {
    }

   public SunX509KeyManagerImpl(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException{
        if (ks == null) {
            return;
        }
        for (Enumeration<String> aliases = ks.aliases();
             aliases.hasMoreElements(); ) {
            String alias = aliases.nextElement();
            if (!ks.isKeyEntry(alias)) {
                continue;
            }
            Key key = ks.getKey(alias, password);
            if (key instanceof PrivateKey == false) {
                continue;
            }
            Certificate[] certs = ks.getCertificateChain(alias);
            if ((certs == null) || (certs.length == 0) ||
                    !(certs[0] instanceof X509Certificate)) {
                continue;
            }
            if (!(certs instanceof X509Certificate[])) {
                Certificate[] tmp = new X509Certificate[certs.length];
                System.arraycopy(certs, 0, tmp, 0, certs.length);
                certs = tmp;
            }

            X509Credentials cred = new X509Credentials((PrivateKey) key,
                    (X509Certificate[]) certs);

            FileInputStream in1 = null;
            credentialsMap.put(alias, cred);
            if (debug != null && Debug.isOn("keymanager")) {
                System.out.println("***");
                System.out.println("found key for : " + alias);
                for (int i = 0; i < certs.length; i++) {
                    System.out.println("chain [" + i + "] = "
                            + certs[i]);
                }
                System.out.println("***");
            }
        }

        try {
           /* String sig="sig";
            String enc="enc";
            X509Credentials certM = getCertM("D:\\360安全浏览器下载\\sm2.mc\\gm.sig.pfx",sig);
            X509Credentials certM2 = getCertM("D:\\360安全浏览器下载\\sm2.mc\\gm.enc.pfx",enc);
            credentialsMap.put(sig, certM);
            credentialsMap.put(enc, certM2);*/
        } catch (Exception e) {
            e.printStackTrace();
        }

    }







    public X509Certificate[] getCertificateChain(String alias) {
        if (alias == null) {
            return null;
        } else {
            SunX509KeyManagerImpl.X509Credentials cred = (SunX509KeyManagerImpl.X509Credentials) this.credentialsMap.get(alias);
            if (cred == null) {
                return null;
            } else {
                return cred.certificates.clone();
            }
        }
    }

    public PrivateKey getPrivateKey(String alias) {
        if (alias == null) {
            return null;
        }
        X509Credentials cred = credentialsMap.get(alias);
        if (cred == null) {
            return null;
        } else {
            return cred.privateKey;
        }
    }


    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        /*
         * We currently don't do anything with socket, but
         * someday we might.  It might be a useful hint for
         * selecting one of the aliases we get back from
         * getClientAliases().
         */

        if (keyTypes == null) {
            return null;
        }
        for (int i = 0; i < keyTypes.length; ++i) {
            String[] aliases = this.getClientAliases(keyTypes[i], issuers);
            if (aliases != null && aliases.length > 0) {
                if (keyTypes[i].equals("EC") || keyTypes[i].equals("EC_EC")) {
                    if (aliases.length == 1) {
                        return aliases[0];
                    }

                    if (aliases.length > 1) {
                        return aliases[0] + ":" + aliases[1];
                    }
                }

                return aliases[0];
            }
        }

        return null;

    }

    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
        return this.chooseClientAlias(keyType, issuers,  null);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        if (keyType == null) {
            return null;
        } else {
            String[] aliases;
            if (issuers != null && issuers.length != 0) {
                aliases = this.getServerAliases(keyType, issuers);
            } else {
                aliases = (String[]) this.serverAliasCache.get(keyType);
                if (aliases == null) {
                    aliases = this.getServerAliases(keyType, issuers);
                    if (aliases == null) {
                        aliases = STRING0;
                    }

                    this.serverAliasCache.put(keyType, aliases);
                }
            }

            if (aliases != null && aliases.length > 0) {
                if (keyType.equals("EC") || keyType.equals("EC_EC")) {
                    if (aliases.length == 1) {
                        return aliases[0];
                    }

                    if (aliases.length > 1) {
                        return aliases[0] + ":" + aliases[1];
                    }
                }

                return aliases[0];
            } else {
                return null;
            }
        }
    }

    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return this.chooseServerAlias(keyType, issuers, null);
    }

    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return this.getAliases(keyType, issuers);
    }

    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return this.getAliases(keyType, issuers);
    }

    private String[] getAliases(String keyType, Principal[] issuers) {
        if (keyType == null) {
            return null;
        } else {
            if (issuers == null) {
                issuers = new X500Principal[0];
            }

            if (!(issuers instanceof X500Principal[])) {
                issuers = convertPrincipals((Principal[]) issuers);
            }

            String sigType;
            if (keyType.contains("_")) {
                int k = keyType.indexOf("_");
                sigType = keyType.substring(k + 1);
                keyType = keyType.substring(0, k);
            } else {
                sigType = null;
            }

            X500Principal[] x500Issuers = (X500Principal[]) issuers;
            // the algorithm below does not produce duplicates, so avoid Set
            ArrayList aliases = new ArrayList();

            Iterator entryIterator = this.credentialsMap.entrySet().iterator();

            while (true) {
                while (true) {
                    String alias;
                    SunX509KeyManagerImpl.X509Credentials credentials;
                    while (true) {
                        X509Certificate[] certs;
                        do {
                            if (!entryIterator.hasNext()) {
                                String[] aliasStrings = (String[]) aliases.toArray(STRING0);
                                return aliasStrings.length == 0 ? null : aliasStrings;
                            }

                            Entry entry = (Entry) entryIterator.next();
                            alias = (String) entry.getKey();
                            credentials = (SunX509KeyManagerImpl.X509Credentials) entry.getValue();
                            certs = credentials.certificates;
                        } while (!keyType.equals(certs[0].getPublicKey().getAlgorithm()));

                        if (sigType == null) {
                            break;
                        }

                        if (certs.length > 1) {
                            if (!sigType.equals(certs[1].getPublicKey().getAlgorithm())) {
                                continue;
                            }
                            break;
                        } else {
                            String sigAlgName = certs[0].getSigAlgName().toUpperCase(Locale.ENGLISH);
                            if (sigAlgName.equals("1.2.156.10197.1.501")
                                    || sigAlgName.toLowerCase().contains("sm3withsm2")) {
                                break;
                            }

                            String pattern = "WITH" + sigType.toUpperCase(Locale.ENGLISH);
                            if (sigAlgName.contains(pattern)) {
                                break;
                            }
                        }
                    }


                    if (issuers.length == 0) {
                        aliases.add(alias);
                        if (debug != null && Debug.isOn("keymanager")) {
                            System.out.println("matching alias: " + alias);
                        }
                    } else {
                        Set certIssuers = credentials.getIssuerX500Principals();

                        for (int i = 0; i < x500Issuers.length; ++i) {
                            if (certIssuers.contains(issuers[i])) {
                                aliases.add(alias);
                                if (debug != null && Debug.isOn("keymanager")) {
                                    System.out.println("matching alias: " + alias);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    private static X500Principal[] convertPrincipals(Principal[] principals) {
        ArrayList list = new ArrayList(principals.length);

        for (int i = 0; i < principals.length; ++i) {
            Principal p = principals[i];
            if (p instanceof X500Principal) {
                list.add((X500Principal) p);
            } else {
                try {
                    list.add(new X500Principal(p.getName()));
                } catch (IllegalArgumentException e) {
                    ;
                }
            }
        }

        return (X500Principal[]) list.toArray(new X500Principal[list.size()]);
    }

    public static class X509Credentials {
        PrivateKey privateKey;
        X509Certificate[] certificates;
        private Set<X500Principal> issuerX500Principals;

        X509Credentials(PrivateKey privateKey, X509Certificate[] certificates) {
            this.privateKey = privateKey;
            this.certificates = certificates;
        }

        synchronized Set<X500Principal> getIssuerX500Principals() {
            if (this.issuerX500Principals == null) {
                this.issuerX500Principals = new HashSet();

                for (int i = 0; i < this.certificates.length; ++i) {
                    this.issuerX500Principals.add(this.certificates[i].getIssuerX500Principal());
                }
            }

            return this.issuerX500Principals;
        }
    }
}
