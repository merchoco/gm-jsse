package com.aliyun.handshake;

import com.aliyun.CipherSuite;
import com.aliyun.ClientRandom;
import com.aliyun.CompressionMethod;
import com.aliyun.ProtocolVersion;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.List;

public class ClientHelloTest {

    @Test
    public void toStringTest() {
        ClientRandom clientRandom = Mockito.mock(ClientRandom.class);
        Mockito.when(clientRandom.toString()).thenReturn("random test");

        List<CipherSuite> suiteList = new ArrayList<CipherSuite>();
        suiteList.add(CipherSuite.NTLS_SM2_WITH_SM4_SM3);

        List<CompressionMethod> methodList = new ArrayList<CompressionMethod>();
        CompressionMethod compressionMethod = new CompressionMethod(0);
        methodList.add(compressionMethod);
        compressionMethod = new CompressionMethod(1);
        methodList.add(compressionMethod);
        compressionMethod = new CompressionMethod(2);
        methodList.add(compressionMethod);

        byte[] bytes = new byte[]{10};
        ClientHello clientHello = new ClientHello(ProtocolVersion.NTLS_1_1, clientRandom, bytes,
                suiteList, methodList);
        String str = clientHello.toString();
        Assert.assertTrue(str.contains("version = NTLSv1.1;"));
        Assert.assertTrue(str.contains("random test"));
        Assert.assertTrue(str.contains("sessionId = 0a"));
        Assert.assertTrue(str.contains("ECC-SM2-WITH-SM4-SM3"));
        Assert.assertTrue(str.contains("compressionMethods = { null, zlib, unknown(2) };"));
    }

    @Test
    public void getBytesTest() throws Exception{
        ClientRandom clientRandom = Mockito.mock(ClientRandom.class);
        Mockito.when(clientRandom.getBytes()).thenReturn("random test".getBytes("UTF-8"));

        List<CipherSuite> suiteList = new ArrayList<CipherSuite>();
        suiteList.add(CipherSuite.NTLS_SM2_WITH_SM4_SM3);

        List<CompressionMethod> methodList = new ArrayList<CompressionMethod>();
        CompressionMethod compressionMethod = new CompressionMethod(0);
        methodList.add(compressionMethod);
        compressionMethod = new CompressionMethod(1);
        methodList.add(compressionMethod);
        compressionMethod = new CompressionMethod(2);
        methodList.add(compressionMethod);

        byte[] bytes = new byte[]{10};
        ClientHello clientHello = new ClientHello(ProtocolVersion.NTLS_1_1, clientRandom, bytes,
                suiteList, methodList);
        bytes = clientHello.getBytes();
        Assert.assertEquals(1, bytes[0]);
        Assert.assertEquals(1, bytes[1]);
        Assert.assertEquals(114, bytes[2]);
        Assert.assertEquals(97, bytes[3]);
        Assert.assertEquals(110, bytes[4]);
        Assert.assertEquals(100, bytes[5]);
        Assert.assertEquals(111, bytes[6]);
        Assert.assertEquals(109, bytes[7]);
        Assert.assertEquals(32, bytes[8]);
        Assert.assertEquals(116, bytes[9]);
        Assert.assertEquals(101, bytes[10]);
        Assert.assertEquals(115, bytes[11]);
        Assert.assertEquals(116, bytes[12]);
    }
}
