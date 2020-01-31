CREATE TABLE nuget_index_state (
  id                INT NOT NULL PRIMARY KEY,
  schema_version    INT NOT NULL,
  last_updated_time BIGINT
);

INSERT INTO nuget_index_state (id, schema_version, last_updated_time) VALUES (
  1,
  0,
  -1
);

CREATE TABLE nuget_index_hashes (
  id SERIAL PRIMARY KEY,
  name VARCHAR(512) NOT NULL,
  version VARCHAR(128),
  file_name VARCHAR(512),
  digest_hex_sha1 CHAR(40),
  digest_hex_md5 CHAR(32)
);

CREATE UNIQUE INDEX nuget_index_hashes_unique_combination ON nuget_index_hashes (name, version, file_name, digest_hex_sha1, digest_hex_md5);