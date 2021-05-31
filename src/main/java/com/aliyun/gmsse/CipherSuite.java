package com.aliyun.gmsse;

import java.util.HashMap;

final public class CipherSuite {
    private static final HashMap<String, CipherSuite> namesToSuites = new HashMap<String, CipherSuite>();

    // ECC-SM2-WITH-SM4-SM3 0x0300  E0 11
    public static final CipherSuite NTLS_SM2_WITH_SM4_SM3 =
            new CipherSuite("ECC",
                    "SM2", "SM4",
                    "SM3", 128,
                    0xe0, 0x13,
            "ECC-SM2-WITH-SM4-SM3",
                    ProtocolVersion.NTLS_1_1);

    private String name;
    private byte[] id;
    private int keyLength;
    /**
     * 密钥交换算法
     */
    private String kexName;
    /**
     * 签名算法
     */
    private String sigName;

    /**
     * 消息摘要
     */
    private final String macName;

    public CipherSuite(String cipherName, String kexName, String sigName, String macName, int keyLength, int id1,
            int id2, String name, ProtocolVersion version) {
        this.kexName = kexName;
        this.sigName = sigName;
        this.macName = macName;
        this.name = name;
        this.keyLength = keyLength;
        this.id = new byte[] { (byte) id1, (byte) id2 };
        namesToSuites.put(name, this);
    }

    public String getName() {
        return name;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public static CipherSuite forName(String name) {
        return (CipherSuite) namesToSuites.get(name);
    }
    public String getMacName() {
        return macName;
    }
    public byte[] getId() {
        return id;
    }

    /**
     * ECC_SM4_SM3  0xe0,ex13
     * @param id1
     * @param id2
     * @param version
     * @return
     */
    public static CipherSuite resolve(int id1, int id2, ProtocolVersion version) {
        if (version == ProtocolVersion.NTLS_1_1) {
            if (id1 == 0xe0) {
                switch (id2) {
                    case 0x13:
                        return NTLS_SM2_WITH_SM4_SM3;
                    default:
                        break;
                }
            }
        }
        return null;
    }

    public String getKeyExchange() {
        return kexName;
    }

    public String getSignature() {
        return sigName;
    }

    public String getAuthType() {
        return kexName + "_" + sigName;
    }
}
