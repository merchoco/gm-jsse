package com.aliyun.gmsse.record;

import java.io.IOException;
import java.io.InputStream;

import com.aliyun.gmsse.RecordStream;

public class AppDataInputStream extends InputStream {

    private RecordStream recordStream;
    /**
     *
     */
    private Handshake handshake;

    public AppDataInputStream(RecordStream recordStream,Handshake handshake) {
        this.recordStream = recordStream;
        this.handshake=handshake;
    }

    @Override
    public int read() throws IOException {
        byte[] buf = new byte[1];
        int ret = read(buf, 0, 1);
        return ret < 0 ? -1 : buf[0] & 0xFF;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        //是否握手成功,客户端建立连接，accept()方法的时候获取的socket流
        Record record = recordStream.read(handshake.isDone());
        if(!handshake.isDone()){
            handshake.startHandshake(record);
        }
        int length = Math.min(record.fragment.length, len);
        System.arraycopy(record.fragment, 0, b, off, length);
        return length;
    }
}
