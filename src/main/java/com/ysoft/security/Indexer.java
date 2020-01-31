package com.ysoft.security;

import java.io.IOException;
import java.io.InputStream;
import java.sql.SQLException;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Indexer {

    private static final Logger LOGGER = LoggerFactory.getLogger(Indexer.class);

    private final NugetMetadataStore nugetMetadataStore;

    public Indexer(NugetMetadataStore nugetMetadataStore) {
        this.nugetMetadataStore = nugetMetadataStore;
    }

    public void index(InputStream zipIn, String expectedName, String expectedVersion) throws IOException, SQLException {
        final NugetMetadata nugetMetadata = NugetReader.analyzeNuget(zipIn, expectedName, expectedVersion);
        for (Map.Entry<String, Map<String, String>> file : nugetMetadata.getHashesForFiles().entrySet()) {
            nugetMetadataStore.addHash(nugetMetadata.getNugetIdentifier().getId(), nugetMetadata.getNugetIdentifier().getVersion(), file.getKey(),
                    file.getValue());
        }
    }
}
