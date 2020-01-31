package com.ysoft.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.*;
import java.util.Map;

public class NugetMetadataStore {
    private static final Logger LOGGER = LoggerFactory.getLogger(NugetMetadataStore.class);

    private static final int REQUIRED_SCHEMA_VERSION = 2;

    private final Connection dbh;

    private final long startTime;

    private final long lastModifiedTime;

    private final String sourceHash;

    public NugetMetadataStore(Connection dbh, long startTime, long lastModifiedTime, String sourceHash) {
        this.dbh = dbh;
        this.startTime = startTime;
        this.lastModifiedTime = lastModifiedTime;
        this.sourceHash = sourceHash;
    }

    public static NugetMetadataStore open(Connection dbh, String hash) throws SQLException, IOException {
        LOGGER.info("Opening metadata store for {}", hash);
        final long startTime = System.currentTimeMillis();
        final int schemaVersion = getSchemaVersion(dbh);
        LOGGER.info("Schema version: {}", schemaVersion);
        updateDbStructure(dbh, schemaVersion);
        final IndexState indexState = getIndexState(dbh, hash);
        LOGGER.info("Index state: {}", indexState);
        return new NugetMetadataStore(dbh, startTime, indexState.getLastModifiedTime(), indexState.getSourceHash());
    }

    private static IndexState getIndexState(Connection dbh, String sourceHash) throws SQLException {
        try(PreparedStatement sourceStatement = dbh.prepareStatement("SELECT * FROM nuget_index_sources WHERE source_hash = ?")){
            sourceStatement.setString(1, sourceHash);
            try(ResultSet sourceResultSet = sourceStatement.executeQuery()){
                if(sourceResultSet.next()) {
                    return new IndexState(sourceResultSet.getLong("last_updated_time"), sourceHash);
                } else {
                    return new IndexState(-1, sourceHash);
                }
            }
        }
    }

    private static int getSchemaVersion(Connection dbh) throws SQLException {
        if(stateTableExists(dbh)){
            try (
                    // The name nuget_index_state is a bit misnomer, which is due to the legacy…
                    PreparedStatement dbStatement = dbh.prepareStatement("SELECT * FROM nuget_index_state WHERE id = 1");
                    ResultSet dbResultSet = dbStatement.executeQuery()
            ) {
                dbResultSet.next();
                return dbResultSet.getInt("schema_version");
            }
        }else{
            return 0;
        }
    }

    private static boolean stateTableExists(Connection dbh) throws SQLException {
        try(
                ResultSet tablesResults = dbh.getMetaData().getTables(dbh.getCatalog(), null, null, null);
        ){
            while(tablesResults.next()){
                final String tableName = tablesResults.getString("TABLE_NAME");
                if(tableName.equals("nuget_index_state")){
                    return true;
                }
            }
            return false;
        }
    }

    private static void updateDbStructure(Connection dbh, int schemaVersion) throws IOException, SQLException {
        for(int i = schemaVersion+1; i <= REQUIRED_SCHEMA_VERSION; i++){
            LOGGER.info("Updating schema to version "+i+"…");
            try (final InputStream in = NugetMetadataStore.class.getResourceAsStream("/schema/" + i + ".sql")) {
                final byte[] buffer = new byte[4096];
                int size;
                final ByteArrayOutputStream out = new ByteArrayOutputStream();
                while((size = in.read(buffer)) != -1){
                    out.write(buffer, 0, size);
                }
                final String sql = out.toString();
                try (Statement statement = dbh.createStatement()) {
                    // I know, it can catch a semicolon inside a string or comment or so, but we can live with that.
                    // This is needed if the DB engine does not support multiple queries in a single batch.
                    for (String sqlPart : sql.split(";")) {
                        statement.addBatch(sqlPart);
                    }
                    statement.addBatch("UPDATE nuget_index_state SET schema_version = "+i);
                    statement.executeBatch();
                }
            }

        }
    }

    public void finish() throws SQLException {
        updateLastUpdated(dbh, startTime, sourceHash);
    }

    private static void updateLastUpdated(Connection dbh, long lastUpdated, String hash) throws SQLException {
        try (PreparedStatement preparedStatement = dbh.prepareStatement(getUpdateLastUpdatedStatement(dbh))) {
            preparedStatement.setLong(1, lastUpdated);
            preparedStatement.setString(2, hash);
            preparedStatement.setLong(3, lastUpdated);
            preparedStatement.execute();
        }
    }

    private static String getUpdateLastUpdatedStatement(Connection dbh) throws SQLException {
        String databaseProductName = dbh.getMetaData().getDatabaseProductName();
        switch (databaseProductName) {
            case "MySQL":
            case "MariaDB":
                return "INSERT INTO nuget_index_sources " +
                        "(last_updated_time, source_hash) VALUES (?, ?) " +
                        "ON DUPLICATE KEY UPDATE last_updated_time = ?";
            case "PostgreSQL":
                return "INSERT INTO nuget_index_sources " +
                        "(last_updated_time, source_hash) VALUES (?, ?) " +
                        "ON CONFLICT (source_hash) DO UPDATE SET last_updated_time = ?";
            default:
                throw new SQLException("Unexpected database: " + databaseProductName);
        }
    }

    public void addHash(String name, String version, String fileName, Map<String, String> hashes) throws SQLException {
        try (PreparedStatement preparedStatement = dbh.prepareStatement(getInsertCommand())) {
            preparedStatement.setString(1, name);
            preparedStatement.setString(2, version);
            preparedStatement.setString(3, fileName);
            preparedStatement.setString(4, hashes.get("sha1"));
            preparedStatement.setString(5, hashes.get("md5"));
            preparedStatement.execute();
        }
    }

    private String getInsertCommand() throws SQLException {
        String databaseProductName = dbh.getMetaData().getDatabaseProductName();
        switch(databaseProductName){
            case "MySQL":
            case "MariaDB":
                return "INSERT IGNORE INTO nuget_index_hashes (name, version, file_name, digest_hex_sha1, digest_hex_md5) VALUES(?, ?, ?, ?, ?)";
            case "PostgreSQL":
                return "INSERT INTO nuget_index_hashes (name, version, file_name, digest_hex_sha1, digest_hex_md5) VALUES(?, ?, ?, ?, ?)" +
                        "ON CONFLICT (name, version, file_name, digest_hex_sha1, digest_hex_md5) DO NOTHING";
            default:
                throw new SQLException("Unexpected database: " + databaseProductName);
        }
    }

    public long getLastModifiedTime() {
        return lastModifiedTime;
    }
}
