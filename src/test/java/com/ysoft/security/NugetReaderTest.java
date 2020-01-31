package com.ysoft.security;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.junit.jupiter.api.Test;

import javax.xml.stream.XMLStreamException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.ysoft.security.NugetReader.analyzeNuget;
import static org.junit.jupiter.api.Assertions.*;

public class NugetReaderTest {

    private NugetMetadata analyzeNugetFile(String path, String expectedName, String expectedVersion) throws IOException {
        try(InputStream in = getClass().getResourceAsStream("/"+path)){
            if(in == null){
                throw new FileNotFoundException(path);
            }
            return analyzeNuget(in, expectedName, expectedVersion);
        }
    }

    private static final Map<String, Map<String, String>> systemGlobalizationHashes = hashesMap(
            entry("lib/MonoAndroid10/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("lib/xamarinwatchos10/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("lib/net45/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("lib/xamarintvos10/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("lib/xamarinmac20/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("lib/MonoTouch10/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("lib/win8/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("lib/xamarinios10/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("lib/wpa81/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("lib/portable-net45%2Bwin8%2Bwp8%2Bwpa81/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("lib/wp80/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            //entry("_rels/.rels", "742fad0664278982d5e97f5515626c52d0b217d0", "98f15a6f3733cdd0c333b83918aeb0d0"),
            //entry("[Content_Types].xml", "b5d7ea43979592a2ffeef800260fd8529f47b36d", "5a6cc58af64194af2bc55bcc867ddec3"),
            entry("dotnet_library_license.txt", "a4cb8479639f7380ba6a632264e887f46fa7a561", "db62529d9c74388f3885fad4b435b3f7"),
            entry("package/services/metadata/core-properties/77885db85c884affa6b80d6e5a56cf58.psmdcp", "5592a5109597abab05cab2729913709e078d73b2", "7dc5495a438658a9492c4aed7788e7c7"),
            entry("ref/MonoAndroid10/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            //entry("ref/netstandard1.3/ko/System.Globalization.xml", "632d95186fa7f021a9bce7f24c8d26c43e30c0a8", "4282b9f0103629108714f370b6e1222f"),
            //entry("ref/netstandard1.3/System.Globalization.xml", "71564073dcf48c24a740273807d9ffa2e8a561c1", "4fe886b0090c10438c5bb543f6c5d2dc"),
            //entry("ref/netstandard1.3/zh-hant/System.Globalization.xml", "ec06d8b60b81eb33ab84abd5bf63f4525737aefe", "11da607afc3c07782540e8fe719153c7"),
            //entry("ref/netstandard1.3/zh-hans/System.Globalization.xml", "6ddb09a5f1c13acd2a2242c4492fdab14eea959b", "f3c1491ef616a2a563eb83e08f2092cf"),
            //entry("ref/netstandard1.3/ja/System.Globalization.xml", "a848e00d99308336c0066b30972be0d8acb0ff5a", "e810f4e9e6028b4c432b41c05ebad6c2"),
            //entry("ref/netstandard1.3/de/System.Globalization.xml", "22ae3ada9772bb1e27c457e068dcfaaa8bcb662e", "1ac187d1c24e59af866837ee8239a79c"),
            //entry("ref/netstandard1.3/ru/System.Globalization.xml", "846bcd342893de6facdd183691782f4185272313", "efc817df6de191d88301ecea957ac825"),
            //entry("ref/netstandard1.3/it/System.Globalization.xml", "2d7048ea9d7360fa92362fc7237c1b53518e79d6", "068098a1d63acbe85d0e08f228ba79be"),
            entry("ref/netstandard1.3/System.Globalization.dll", "879325a6b71bbdea6f2d2f9d85311559653b4f11", "c481520a478dc704f80f25fd3894b563"),
            //entry("ref/netstandard1.3/es/System.Globalization.xml", "5da83bd1fcfacf7d6e6c501b9b3648d3f86135af", "b6f6ade3994d858aca7618775aaf40d2"),
            //entry("ref/netstandard1.3/fr/System.Globalization.xml", "e5639262d8908200a8a58f89c456256b1633a29d", "8cc404253cdc98e9450b027f6ec590a8"),
            entry("ref/xamarinwatchos10/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("ref/net45/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("ref/xamarintvos10/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("ref/xamarinmac20/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("ref/MonoTouch10/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            //entry("ref/netcore50/ko/System.Globalization.xml", "632d95186fa7f021a9bce7f24c8d26c43e30c0a8", "4282b9f0103629108714f370b6e1222f"),
            //entry("ref/netcore50/System.Globalization.xml", "71564073dcf48c24a740273807d9ffa2e8a561c1", "4fe886b0090c10438c5bb543f6c5d2dc"),
            //entry("ref/netcore50/zh-hant/System.Globalization.xml", "ec06d8b60b81eb33ab84abd5bf63f4525737aefe", "11da607afc3c07782540e8fe719153c7"),
            //entry("ref/netcore50/zh-hans/System.Globalization.xml", "6ddb09a5f1c13acd2a2242c4492fdab14eea959b", "f3c1491ef616a2a563eb83e08f2092cf"),
            //entry("ref/netcore50/ja/System.Globalization.xml", "a848e00d99308336c0066b30972be0d8acb0ff5a", "e810f4e9e6028b4c432b41c05ebad6c2"),
            //entry("ref/netcore50/de/System.Globalization.xml", "22ae3ada9772bb1e27c457e068dcfaaa8bcb662e", "1ac187d1c24e59af866837ee8239a79c"),
            //entry("ref/netcore50/ru/System.Globalization.xml", "846bcd342893de6facdd183691782f4185272313", "efc817df6de191d88301ecea957ac825"),
            //entry("ref/netcore50/it/System.Globalization.xml", "2d7048ea9d7360fa92362fc7237c1b53518e79d6", "068098a1d63acbe85d0e08f228ba79be"),
            entry("ref/netcore50/System.Globalization.dll", "879325a6b71bbdea6f2d2f9d85311559653b4f11", "c481520a478dc704f80f25fd3894b563"),
            //entry("ref/netcore50/es/System.Globalization.xml", "5da83bd1fcfacf7d6e6c501b9b3648d3f86135af", "b6f6ade3994d858aca7618775aaf40d2"),
            //entry("ref/netcore50/fr/System.Globalization.xml", "e5639262d8908200a8a58f89c456256b1633a29d", "8cc404253cdc98e9450b027f6ec590a8"),
            //entry("ref/netstandard1.0/ko/System.Globalization.xml", "632d95186fa7f021a9bce7f24c8d26c43e30c0a8", "4282b9f0103629108714f370b6e1222f"),
            //entry("ref/netstandard1.0/System.Globalization.xml", "71564073dcf48c24a740273807d9ffa2e8a561c1", "4fe886b0090c10438c5bb543f6c5d2dc"),
            //entry("ref/netstandard1.0/zh-hant/System.Globalization.xml", "ec06d8b60b81eb33ab84abd5bf63f4525737aefe", "11da607afc3c07782540e8fe719153c7"),
            //entry("ref/netstandard1.0/zh-hans/System.Globalization.xml", "6ddb09a5f1c13acd2a2242c4492fdab14eea959b", "f3c1491ef616a2a563eb83e08f2092cf"),
            //entry("ref/netstandard1.0/ja/System.Globalization.xml", "a848e00d99308336c0066b30972be0d8acb0ff5a", "e810f4e9e6028b4c432b41c05ebad6c2"),
            //entry("ref/netstandard1.0/de/System.Globalization.xml", "22ae3ada9772bb1e27c457e068dcfaaa8bcb662e", "1ac187d1c24e59af866837ee8239a79c"),
            //entry("ref/netstandard1.0/ru/System.Globalization.xml", "846bcd342893de6facdd183691782f4185272313", "efc817df6de191d88301ecea957ac825"),
            //entry("ref/netstandard1.0/it/System.Globalization.xml", "2d7048ea9d7360fa92362fc7237c1b53518e79d6", "068098a1d63acbe85d0e08f228ba79be"),
            entry("ref/netstandard1.0/System.Globalization.dll", "fc66f3384835722177dc523e100574bd06c45725", "849f648b4f96278669f6410f8c159f94"),
            //entry("ref/netstandard1.0/es/System.Globalization.xml", "5da83bd1fcfacf7d6e6c501b9b3648d3f86135af", "b6f6ade3994d858aca7618775aaf40d2"),
            //entry("ref/netstandard1.0/fr/System.Globalization.xml", "e5639262d8908200a8a58f89c456256b1633a29d", "8cc404253cdc98e9450b027f6ec590a8"),
            entry("ref/win8/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("ref/xamarinios10/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("ref/wpa81/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("ref/portable-net45%2Bwin8%2Bwp8%2Bwpa81/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("ref/wp80/_._", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "d41d8cd98f00b204e9800998ecf8427e"),
            entry("System.Globalization.nuspec", "07689ff76a416c988f6af94cd7cc4b10ddb95e08", "44ff82802f7d390bfedae1e5c5be6c5e"),
            entry("ThirdPartyNotices.txt", "58633a0b1cc282fa6ec4ca32d4b9327319ca31fe", "c967cb8266866e70f817fee256966091")
    );

    private static final Map<String, Map<String, String>> microsoftNetcoreRuntimeCoreclrArmHashes = hashesMap(
            //entry("_rels/.rels", "fe496bc9c2a148400d4648a2c4b4c7dd2db63a9a", "80008d2f71d952183263cc6739b48c90"),
            entry("Microsoft.NETCore.Runtime.CoreCLR-arm.nuspec", "20d364b0cce512510c0a8e5556e7d5a09171f401", "35c2b666457bdc1abbccb96153c564b1"),
            //entry("[Content_Types].xml", "85095f137c96204b5099b3085885acfbde04108b", "9c542780fe63324caca20a23f3168c6d"),
            entry("runtimes/win8-arm/lib/dotnet/mscorlib.ni.dll", "84b5407977ffce80854d9203ebf6d36e4c69f374", "6980c421ab76c555600d57d608abd58e"),
            entry("runtimes/win8-arm/native/coreclr.dll", "f03b24c2be5b908d504371b351484100bfc27768", "37238f2bb0276d18c9585530104ef70b"),
            entry("runtimes/win8-arm/native/mscordaccore.dll", "4b0af8bb4b2313682af44c4d72aec4069ebec51e", "6fae425f7e27c6ff217266b40c83f160"),
            entry("runtimes/win8-arm/native/mscordbi.dll", "f59a9a4e1cbc1daad601e0e196987871daf755fe", "2cc25b01beee5e72cd5d0893516c2aba"),
            entry("runtimes/win8-arm/native/dbgshim.dll", "00b7dbcf9cd520913375028e64a2a40655408e50", "bb421ab20b557d885157a035634f0e9b"),
            entry("runtimes/win8-arm/native/mscorrc.dll", "319d8fbdba7552f7546d4e64bafc829153029f90", "dc8bfbd9ed5172ddf4c7c402118c1b4b"),
            entry("runtimes/win8-arm/native/clretwrc.dll", "d7e56c09b3e9e40f8a4cdfee45d5aae9f8832490", "85dffa2f3dbae07c6ab0731f1f837f03"),
            entry("runtimes/win8-arm/native/mscorrc.debug.dll", "11169d8018227b7bdc77eddf114aefa4db19f33f", "b65e2e3baf57a333019f772eb3f4eb4c"),
            entry("package/services/metadata/core-properties/c1cbeaed81514106b6b7971ac193f132.psmdcp", "5fb4a8f7f8303e347cbf30a3e8701f2e14f7a844", "1f7935ebc3353d6c0894d00d73616372")
            // damaged: entry("ref/dotnet/_._", "688934845f22049cb14668832efa33d45013b6b9", "598f4fe64aefab8f00bcbea4c9239abf")
    );

    private static final Map<String, Map<String, String>> microsoftAspnetRazorHashes = hashesMap(
        entry("lib/net40/System.Web.Razor.dll", "d6b7cd752f0ff7b9f773d544add6a5ea00158599", "cd4ddc9c5b2695018d6e7c2950e7d82f"),
        //entry("lib/net40/System.Web.Razor.xml", "4e2f4e963f640112679f70f7a8aeab746342f7b1", "2aa1d44a5b99b443f614ad6890cdb92b"),
        //entry("_rels/.rels", "7bc360ddecbd16668555b48785e202558b67f3fc", "fec47ef79c06556ef9f3bc8f89c02075"),
        entry("Microsoft.AspNet.Razor.nuspec", "05d426f9e8ecb4685efe1436357fd61bcc5d6df2", "2b70d4b4a93c8146db24138faa844c8c"),
        //entry("[Content_Types].xml", "d52e5937a775c3df3eee3b5cac6bbbbb1d884009", "4a8b92ec365e327ad1c1cae004d3c088"),
        entry("package/services/metadata/core-properties/37cf22fae31a4489a4df544d33fed45a.psmdcp", "4223c8c09f0f99751772dcb9ec0cad70af45e88b", "4892743e40333517a6aecab561e4143c"),
        entry(".signature.p7s", "84923efb62418eedd119be96901a624d4f87cf99", "c5b87f4ac7119eb7ebbff954993e9937")
    );

    private static final Map<String, Map<String, String>> netMqHashes = hashesMap(
        entry(".signature.p7s", "f62ab9b16f5630208353904ea7cae72784b60d5c", "e55402a31e9d8bf9a0a4ee8e1bcab495"),
        entry("package/services/metadata/core-properties/35baa1c9e346418996e5dcf9bbc4c861.psmdcp", "e5628ff74af0a48a7f367792bf50e94301eb6d74", "98d973ededa8490ad19493996d6a47d1"),
        entry("package/services/metadata/core-properties/25d54e2d9f1b429386de7b9853bf46f9.psmdcp", "bcdeace599c87a895ae8832177adc4bf92f5dad7", "cdfd39d415fa39bdf2052b4e65ef6f2c"),
        //entry("lib/netstandard2.0/NetMQ.xml", "9067824d07b0b457b7846dc18ecd1f5467a0d206", "8358926b643d647167cc4e527a4a8c39"),
        entry("lib/netstandard2.0/NetMQ.pdb", "2923e5f0088ca2a24f87613b113419e2d9e5914b", "65569b7afcbe1d46ca5820205ab5f514"),
        entry("lib/netstandard2.0/NetMQ.dll", "8fef6ef59442061ead95457649b3d62a69775c6c", "b15546f1a77a5dda915c8bc792c2283d"),
        //entry("lib/netstandard1.6/NetMQ.xml", "96354c3655d7e95718759b2969dd351eb20059e5", "e332c83a76c30c57e47985ca26fd029d"),
        entry("lib/netstandard1.6/NetMQ.pdb", "d2fc620dee4fa297ae826ecb378ab63c4b358b57", "6e59b2c6a6ef2542c3fd9d6b6922c5c1"),
        entry("lib/netstandard1.6/NetMQ.dll", "65fbf6ffdc6bb648628921d85423c85013920c0d", "0c423c8978b33dce16c6903f827109bd"),
        //entry("lib/net40/NetMQ.xml", "cf7f6c9a2f59c121e4d6550239503c6210d9a9f0", "59bd1e8c3920f08970415fc71d1c27ce"),
        entry("lib/net40/NetMQ.pdb", "5dd57094e2ec802554abbcf0e63fac3c3e870128", "8f70a7bc3c0508448a95cc06f81866d7"),
        entry("lib/net40/NetMQ.dll", "6c8217c37c7f50e23d5b4948873ad73327945d74", "05c06b5716822bed55fb4cab8b9193cb"),
        //entry("_rels/.rels", "?", "?"),
        //entry("[Content_Types].xml", "?", "?"),
        entry("NetMQ.nuspec", "cdd0a117da95745fcb7a86c541a0c2a6ae184238", "8fece78f2bc2ae511f0c2ac9b1386894")
    );


    private static Map.Entry<String, Map<String, String>> entry(String file, String sha1, String md5) {
        final Map<String, String> hashes = new HashMap<>();
        hashes.put("sha1", sha1.toUpperCase());
        hashes.put("md5", md5.toUpperCase());
        return new ImmutablePair<>(file, Collections.unmodifiableMap(hashes));
    }

    private static Map<String, Map<String, String>> hashesMap(Map.Entry<String, Map<String, String>>... entries){
        //return Arrays.stream(entries).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        final Map<String, Map<String, String>> map = new HashMap<>();
        for (Map.Entry<String, Map<String, String>> entry : entries) {
            map.put(entry.getKey(), entry.getValue());
        }
        return Collections.unmodifiableMap(map);
    }

    @Test
    public void testSomeRandomNuget() throws IOException {
        assertEquals(systemGlobalizationHashes, analyzeNugetFile("System.Globalization.4.3.0.nupkg", "System.Globalization", "4.3.0").getHashesForFiles());
    }

    @Test
    public void testNugetWithEmptyFile() throws IOException {
        final Map<String, Map<String, String>> hashesForFiles = new HashMap<>(analyzeNugetFile("Microsoft.NETCore.Runtime.CoreCLR-arm-1.0.0.nupkg", "Microsoft.NETCore.Runtime.CoreCLR-arm", "1.0.0").getHashesForFiles());
        hashesForFiles.remove("ref/dotnet/_._"); // remove damaged
        assertEquals(microsoftNetcoreRuntimeCoreclrArmHashes.keySet(), hashesForFiles.keySet());
        assertEquals(microsoftNetcoreRuntimeCoreclrArmHashes, hashesForFiles);
    }

    @Test
    public void testSomeOtherTroublesomeNuget() throws IOException {
        // This NuGet used to cause issues with hashing the manifest file, because of using non-zero offset when calling Hashing.HashingInputStream.read(byte[], int, int). Ideally, we would create a test for this scenario.
        final Map<String, Map<String, String>> hashesForFiles = new HashMap<>(analyzeNugetFile("Microsoft.AspNet.Razor-2.0.20715.0.nupkg", "Microsoft.AspNet.Razor", "2.0.20715.0").getHashesForFiles());
        assertEquals(microsoftAspnetRazorHashes, hashesForFiles);
    }

    @Test
    public void testPackageWithDuplicateBlacklistedFiles() throws IOException {
        // This should proceed, as the duplicate files are excluded.
        final Map<String, Map<String, String>> hashesForFiles = new HashMap<>(analyzeNugetFile("netmq.4.0.0.207.nupkg", "NetMQ", "4.0.0.207").getHashesForFiles());
        assertEquals(netMqHashes, hashesForFiles);
    }

    @Test
    void testGetNugetIdentifierFromManifest() throws IOException, XMLStreamException, NoSuchAlgorithmException {
        try (Hashing.HashingInputStream in = new Hashing.HashingInputStream(getClass().getResourceAsStream("/Microsoft.AspNet.Razor.nuspec"))) {
            assertEquals(new NugetIdentifier("Microsoft.AspNet.Razor", "2.0.20715.0"), NugetReader.getNugetIdentifierFromManifest(in));
            while(in.read() != -1){
                // Eat it!
            }
            final Map<String, String> hashes = in.finalizeHashes();
            assertEquals(hashes, microsoftAspnetRazorHashes.get("Microsoft.AspNet.Razor.nuspec"));
        }
    }
}