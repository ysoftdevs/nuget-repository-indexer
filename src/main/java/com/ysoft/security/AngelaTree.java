package com.ysoft.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SortedSet;

public class AngelaTree {
    public static byte[] merkleSorted(List<String> dataList){
        final String[] dataArray = dataList.toArray(new String[0]);
        Arrays.sort(dataArray);
        final byte[][] raw = new byte[dataList.size()][];
        for (int i = 0; i < dataArray.length; i++) {
            raw[i] = dataArray[i].getBytes(StandardCharsets.UTF_8);
        }
        return merkle(raw);
    }
    public static byte[] merkle(List<String> dataList){
        final byte[][] raw = new byte[dataList.size()][];
        for (int i = 0; i < dataList.size(); i++) {
            raw[i] = dataList.get(i).getBytes(StandardCharsets.UTF_8);
        }
        return merkle(raw);
    }
    public static byte[] merkle(SortedSet<String> dataList){
        return merkle(new ArrayList<>(dataList));
    }
    public static byte[] merkle(byte[]... dataArray){
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
        for (byte[] bytes : dataArray) {
            digest.update((byte)((bytes.length >>> 24) & 0xff));
            digest.update((byte)((bytes.length >>> 16) & 0xff));
            digest.update((byte)((bytes.length >>>  8) & 0xff));
            digest.update((byte)((bytes.length       ) & 0xff));
            digest.update(bytes);
        }
        return digest.digest();
    }
}
