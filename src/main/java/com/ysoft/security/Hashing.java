package com.ysoft.security;

import javax.xml.bind.DatatypeConverter;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class Hashing {
    private static final Map<String, String> HASHES;
    static {
        final HashMap<String, String> map = new HashMap<>();
        map.put("sha1", "SHA1");
        map.put("md5", "MD5");
        HASHES = Collections.unmodifiableMap(map);
    }

    public static Map<String, String> hash(InputStream in) throws NoSuchAlgorithmException, IOException {
        final MessageDigest[] digestsArray = new MessageDigest[Hashing.HASHES.size()];
        final Map<String, MessageDigest> digestsMap = createDigestsMap(digestsArray);
        final byte[] buffer = new byte[4096];
        int len;
        while ((len = in.read(buffer)) != -1) {
            for (final MessageDigest digest: digestsArray) {
                digest.update(buffer, 0, len);
            }
        }
        final Map<String, String> hashes = finalizeHashes(digestsMap);
        return hashes;
    }

    private static Map<String, String> finalizeHashes(Map<String, MessageDigest> digestsMap) {
        final Map<String, String> hashes = new HashMap<>();
        for (final Map.Entry<String, MessageDigest> md : digestsMap.entrySet()) {
            hashes.put(md.getKey(), DatatypeConverter.printHexBinary(md.getValue().digest()));
        }
        return hashes;
    }

    private static Map<String, MessageDigest> createDigestsMap(MessageDigest[] digestsArray) throws NoSuchAlgorithmException {
        final Map<String, MessageDigest> digestsMap = new HashMap<>();
        int i = 0;
        for (final Map.Entry<String, String> digestEntry : Hashing.HASHES.entrySet()) {
            final MessageDigest messageDigest = MessageDigest.getInstance(digestEntry.getValue());
            digestsArray[i] = messageDigest;
            digestsMap.put(digestEntry.getKey(), messageDigest);
            i++;
        }
        return digestsMap;
    }

    public static class HashingInputStream extends FilterInputStream {
        private final MessageDigest[] digestsArray = new MessageDigest[Hashing.HASHES.size()];
        private final Map<String, MessageDigest> digestsMap = createDigestsMap(digestsArray);

        public HashingInputStream(InputStream in) throws NoSuchAlgorithmException {
            super(in);
        }

        @Override
        public int read() throws IOException {
            final int i = super.read();
            if(i != -1){
                for (final MessageDigest digest: digestsArray) {
                    digest.update((byte)i);
                }
            }
            return i;
        }

        @Override
        public int read(byte[] b) throws IOException {
            return read(b, 0, b.length);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            final int count = super.read(b, off, len);
            if(count>0) { // skip EOFs and empty reads
                for (final MessageDigest digest : digestsArray) {
                    digest.update(b, off, count);
                }
            }
            return count;
        }

        @Override
        public long skip(long n) throws IOException {
            // not very efficient implementation, but I suppose this will not be used frequently.
            long skipped = 0;
            long toSkip = n;
            while (toSkip > 0){ // prevents integer overflow
                if(read() == -1){
                    break;
                }
                skipped++;
                toSkip--;
            }
            return skipped;
        }

        @Override
        public synchronized void mark(int readlimit) {
            // Not sure about the correct behavior, so I'll try to throw an unchecked exception in order to note that there is something wrong.
            throw new RuntimeException("Mark is not supported.");
        }

        @Override
        public synchronized void reset() throws IOException {
            throw new IOException("Reset is not supported.");
        }

        @Override
        public boolean markSupported() {
            return false;
        }

        public Map<String, String> finalizeHashes(){
            return Hashing.finalizeHashes(digestsMap);
        }
    }

}
