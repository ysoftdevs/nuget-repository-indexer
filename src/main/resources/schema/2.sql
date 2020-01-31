ALTER TABLE nuget_index_state
  DROP COLUMN last_updated_time; -- moved to another table

CREATE TABLE nuget_index_sources (
  id                SERIAL       PRIMARY KEY,
  source_hash       VARCHAR(128) NOT NULL UNIQUE,
  last_updated_time BIGINT       NOT NULL,
  note              VARCHAR(256) NULL
)