package com.aliyun.gmsse;

import org.junit.Assert;
import org.junit.Test;

public class CipherSuiteTest {

    @Test
    public void getTest() {
        String str = CipherSuite.NTLS_SM2_WITH_SM4_SM3.getName();
        Assert.assertEquals("ECC-SM2-WITH-SM4-SM3", str);

        /**
         * 密钥交换
         */
        str = CipherSuite.NTLS_SM2_WITH_SM4_SM3.getKeyExchange();
        Assert.assertEquals("SM2", str);

        /**
         * 签名
         */
        str = CipherSuite.NTLS_SM2_WITH_SM4_SM3.getSignature();
        Assert.assertEquals("SM4", str);

        /**
         * 摘要
         */
        str = CipherSuite.NTLS_SM2_WITH_SM4_SM3.getMacName();
        Assert.assertEquals("SM3", str);



        CipherSuite cipherSuite = CipherSuite.forName("name");
        Assert.assertNull(cipherSuite);
    }

    @Test
    public void resolveTest() {
        /**
         * SSL的加密套件都有对应的2个字节
         * TLS定义了几百个加密套件
         * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
         * 每个加密套件使用2个16进制代表。
         * 国密的定义的加密套件 需要参照国密规范协议。自行定义加密套件
         * http://www.doc88.com/p-9029134947623.html
         * 0xe0,0x13就是ECC_SM4_SM3套件
         *
         * ECC_SM4_SM3套件，非对称加密算法为SM2，对称加密算法为SM4，摘要算法为SM3。
         *
         * SM2为非对称加密，基于ECC。该算法已公开。由于该算法基于ECC，故其签名速度与秘钥生成速度都快于RSA。
         * ECC 256位（SM2采用的就是ECC 256位的一种）安全强度比RSA 2048位高，但运算速度快于RSA。
         *
         * SM3 消息摘要。可以用MD5作为对比理解。该算法已公开。校验结果为256位。
         *
         * SM4 无线局域网标准的分组数据算法。对称加密，密钥长度和分组长度均为128位
         */
        CipherSuite cipherSuite = CipherSuite.resolve(0xe0, 0x13, ProtocolVersion.NTLS_1_1);

        Assert.assertEquals(cipherSuite, CipherSuite.NTLS_SM2_WITH_SM4_SM3);

        cipherSuite = CipherSuite.resolve(0x00, 0x13, ProtocolVersion.NTLS_1_1);
        Assert.assertNull(cipherSuite);

        cipherSuite = CipherSuite.resolve(0xe0, 0xe3, ProtocolVersion.NTLS_1_1);
        Assert.assertNull(cipherSuite);
    }
}
