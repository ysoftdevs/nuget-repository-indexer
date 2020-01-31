package com.ysoft.security;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NugetReader {
    private static final Logger LOGGER = LoggerFactory.getLogger(NugetReader.class);

    private NugetReader() {
    }

    public static NugetMetadata analyzeNuget(InputStream in, String expectedName, String expectedVersion) throws IOException {
        NugetIdentifier nugetIdentifier = null;
        final Map<String, Map<String, String>> hashesForFiles = new HashMap<>();
        try (ZipArchiveInputStream zip = new ZipArchiveInputStream(new BufferedInputStream(in))) {
            ArchiveEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                final Hashing.HashingInputStream hashIn = new Hashing.HashingInputStream(zip);
                if (isManifest(entry)) {
                    if (nugetIdentifier == null) {
                        nugetIdentifier = getNugetIdentifierFromManifest(hashIn);
                    } else {
                        throw new IOException("Multiple NuGet manifests!");
                    }
                }
                consumeStream(hashIn); // read the rest
                if (!isBlacklistedFile(entry.getName())) {
                    final Object previous = hashesForFiles.put(entry.getName(), hashIn.finalizeHashes());
                    if (previous != null && entry.getName().toLowerCase().endsWith(".dll")) {
                        throw new IOException("Multiple occurrences of file: " + entry.getName());
                    }
                }
            }
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        } catch (XMLStreamException e) {
            throw new IOException(e);
        }
        if (nugetIdentifier == null) {
            throw new IOException("Missing manifest file");
        }
        if (expectedName != null) {
            if (!expectedName.equalsIgnoreCase(nugetIdentifier.getId())) {
                throw new IOException("Does not equal: " + expectedName + " and " + nugetIdentifier.getId());
            }
        }
        if (expectedVersion != null) {
            if (!expectedVersion.equals(nugetIdentifier.getVersion())) {
                throw new IOException("Does not equal: " + expectedVersion + " and " + nugetIdentifier.getVersion());
            }
        }
        final NugetMetadata nugetMetadata = new NugetMetadata(nugetIdentifier, hashesForFiles);
        LOGGER.info("name: " + nugetIdentifier.getId() + ", version: " + nugetIdentifier.getVersion());
        return nugetMetadata;
    }

    private static boolean isBlacklistedFile(String name) {
        final String nn = name.toLowerCase();
        return nn.endsWith(".xml") || nn.endsWith("/.rels");
    }

    private static void consumeStream(InputStream hashIn) throws IOException {
        final byte[] buffer = new byte[4096];
        //noinspection StatementWithEmptyBody
        while (hashIn.read(buffer) > 0) {
            // just consume in order to compute the proper hash
        }
    }

    public static NugetIdentifier getNugetIdentifierFromManifest(InputStream input) throws XMLStreamException, IOException {
        String id = null;
        String version = null;
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false); // This disables DTDs entirely for that factory
        xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", false); // disable external entities
        final XMLEventReader xmlEventReader = xmlInputFactory.createXMLEventReader(new NonClosableInputStream(input));
        while (xmlEventReader.hasNext()) {
            final XMLEvent event = xmlEventReader.nextEvent();
            if (event.isStartElement()) {
                switch (event.asStartElement().getName().getLocalPart()) {
                    case "id":
                        if (id == null) {
                            id = xmlEventReader.nextEvent().asCharacters().getData();
                        } else {
                            throw new IOException("Multiple id elements.");
                        }
                        break;
                    case "version":
                        if (version == null) {
                            version = xmlEventReader.nextEvent().asCharacters().getData();
                        } else {
                            throw new IOException("Multiple version elements.");
                        }
                        break;
                    default:
                        //ignore
                }
            }
        }
        if (id == null) {
            throw new IOException("Cannot find NuGet id");
        }
        if (version == null) {
            throw new IOException("Cannot find NuGet version");
        }
        return new NugetIdentifier(id, version);
    }

    private static boolean isManifest(ArchiveEntry zipEntry) {
        return zipEntry.getName().toLowerCase().endsWith(".nuspec") && !zipEntry.getName().contains("/");
    }

}
