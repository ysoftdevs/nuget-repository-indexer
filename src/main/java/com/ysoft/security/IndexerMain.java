package com.ysoft.security;

import org.apache.commons.cli.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.*;
import java.util.regex.Pattern;

import static java.util.Arrays.asList;

public class IndexerMain {
    private static final Logger LOGGER = LoggerFactory.getLogger(IndexerMain.class);

    private static final Options options = new Options();

    private static final String OPT_SOURCE_TYPE = "source-type";
    private static final String OPT_NEXUS_NUGET_PATH = "nexus-nuget-path";
    private static final String OPT_NEXUS_SERVER_ID = "nexus-server-identity";
    private static final String OPT_ARTIFACTORY_URL = "artifactory-url";
    private static final String OPT_ARTIFACTORY_USERNAME = "artifactory-username";
    private static final String OPT_ARTIFACTORY_PASSFILE = "artifactory-passfile";
    private static final String OPT_ARTIFACTORY_REPOSITORY = "artifactory-repository";
    private static final String OPT_ARTIFACTORY_EXCLUDE = "artifactory-exclude-prefix";
    private static final String OPT_OUTPUT_DB_URL = "output-db-url";
    private static final String OPT_OUTPUT_DB_PROPERTIES = "output-db-properties";

    static {
        options.addOption(Option.builder().longOpt(OPT_SOURCE_TYPE).required().desc("Type of source. Allowed values: “nexus” and “artifactory”").numberOfArgs(1).build());
        options.addOption(Option.builder().longOpt(OPT_NEXUS_NUGET_PATH).desc("Path to nuget storage, multiple values can be separated by “" + File.pathSeparator + "”").numberOfArgs(1).build());
        options.addOption(Option.builder().longOpt(OPT_NEXUS_SERVER_ID).desc("Unique identifier of indexed server, preferably URL. This is used just for distinguishing between various instances.").numberOfArgs(1).build());
        options.addOption(Option.builder().longOpt(OPT_ARTIFACTORY_URL).desc("URL to JFrog Artifactory.").numberOfArgs(1).build());
        options.addOption(Option.builder().longOpt(OPT_ARTIFACTORY_USERNAME).desc("Username for JFrog Artifactory.").numberOfArgs(1).build());
        options.addOption(Option.builder().longOpt(OPT_ARTIFACTORY_PASSFILE).desc("File with password for JFrog Artifactory.").numberOfArgs(1).build());
        options.addOption(Option.builder().longOpt(OPT_ARTIFACTORY_REPOSITORY).desc("Repositories to index. It can be used multiple times.").numberOfArgs(Option.UNLIMITED_VALUES).build());
        options.addOption(Option.builder().longOpt(OPT_ARTIFACTORY_EXCLUDE).desc("Prefixes to exclude.").numberOfArgs(Option.UNLIMITED_VALUES).build());
        options.addOption(Option.builder().longOpt(OPT_OUTPUT_DB_URL).required().desc("JDBC URL for storage DB").numberOfArgs(1).build());
        options.addOption(Option.builder().longOpt(OPT_OUTPUT_DB_PROPERTIES).desc("Location of file of properties for DB connection.").numberOfArgs(1).build());
    }

    public static void main(String[] args) throws SQLException, IOException, ClassNotFoundException, InterruptedException {
        final CommandLineParser parser = new DefaultParser();
        final CommandLine cmd;
        final NugetSource source;
        final Properties dbProps;
        try {
            cmd = parser.parse(options, args);
            if(!cmd.getArgList().isEmpty()){
                throw new ParseException("Unexpected extra arguments: "+ cmd.getArgList());
            }
            LOGGER.info("Constructing nuget source…");
            source = getNugetSource(cmd);
            LOGGER.info("Constructed nuget source: {}", source);
            dbProps = parseDbProps(cmd);
        } catch (ParseException e) {
            System.err.println("Bad parameters: " + e.getMessage());
            help(System.err);
            System.exit(1);
            return; // satisfy compiler
        }
        try{
            index(source, cmd.getOptionValue(OPT_OUTPUT_DB_URL), dbProps);
        }catch (SQLException e){
            System.err.println("SQL Exception(s):");
            for(SQLException sqlException = e; sqlException != null; sqlException = sqlException.getNextException()){
                sqlException.printStackTrace();
            }
            System.exit(1);
        }
    }

    private static Properties parseDbProps(CommandLine cmd) throws ParseException {
        final Properties dbProps = new Properties();
        final String dbPropertiesFile = cmd.getOptionValue(OPT_OUTPUT_DB_PROPERTIES);
        if (dbPropertiesFile != null) {
            try (final FileInputStream inputStream = new FileInputStream(dbPropertiesFile)) {
                dbProps.load(inputStream);
            } catch (IOException e) {
                throw new ParseException("Error when loading DB properties file: " + e.getMessage());
            }
        }
        return dbProps;
    }

    private static NugetSource getNugetSource(CommandLine cmd) throws ParseException {
        final String sourceType = cmd.getOptionValue(OPT_SOURCE_TYPE);
        switch (sourceType) {
            case "nexus":
                return new NexusNugetSource(parsePaths(cmd.getOptionValue(OPT_NEXUS_NUGET_PATH)), cmd.getOptionValue(OPT_NEXUS_SERVER_ID));
            case "artifactory":
                final String password;
                try (BufferedReader reader = new BufferedReader(new FileReader(cmd.getOptionValue(OPT_ARTIFACTORY_PASSFILE)))) {
                    password = reader.readLine();
                } catch (IOException e) {
                    throw new ParseException("Error when reading password file for artifactory: "+e.getMessage());
                }
                final String username = cmd.getOptionValue(OPT_ARTIFACTORY_USERNAME);
                final String[] repositories = cmd.getOptionValues(OPT_ARTIFACTORY_REPOSITORY);
                if(repositories == null){
                    throw new ParseException("Please specify at least one repository.");
                }
                final TreeSet<String> exclusions = new TreeSet<>(asList(Optional.ofNullable(cmd.getOptionValues(OPT_ARTIFACTORY_EXCLUDE)).orElseGet(() -> new String[0])));
                return new ArtifactoryNugetSource(cmd.getOptionValue(OPT_ARTIFACTORY_URL), username, password, Arrays.asList(repositories), exclusions);
            default:
                throw new ParseException("Unknown source type: " + sourceType);
        }
    }

    private static void help(PrintStream out) {
        help(new PrintWriter(out, true));
    }

    private static void help(PrintWriter writer) {
        new HelpFormatter().printHelp(
                writer,
                HelpFormatter.DEFAULT_WIDTH,
                "java -jar nuget-indexer.jar",
                null,
                options,
                HelpFormatter.DEFAULT_LEFT_PAD,
                HelpFormatter.DEFAULT_DESC_PAD,
                null
        );
    }

    private static List<String> parsePaths(String pathString) {
        return asList(pathString.split(Pattern.quote(File.pathSeparator)));
    }

    private static void index(NugetSource source, String connString, Properties dbProps) throws IOException, SQLException {
        if(!org.postgresql.Driver.isRegistered()){
            org.postgresql.Driver.register();
        }
        org.mariadb.jdbc.Driver.class.getName();
        try (Connection dbh = DriverManager.getConnection(connString, updatedProps(dbProps))) {
            final NugetMetadataStore nugetMetadataStore = NugetMetadataStore.open(dbh, source.getHash());
            final long lastModifiedTime = nugetMetadataStore.getLastModifiedTime();
            final Indexer indexer = new Indexer(nugetMetadataStore);
            LOGGER.info("Start indexing {}…", source);
            source.index(lastModifiedTime, indexer);
            nugetMetadataStore.finish();
            LOGGER.info("Finished indexing {}…", source);
        }
    }

    private static Properties updatedProps(Properties dbProps) {
        final Properties clone = (Properties) dbProps.clone();
        clone.put("allowMultiQueries", "true");
        return clone;
    }

}
