-- lakeFS authorization store.
--
-- Every key column uses COLLATE "C" so that ordering is bytewise and matches the
-- in-memory store, and so that LIKE 'prefix%' can use the index. Deletes rely on
-- ON DELETE CASCADE instead of application code.

CREATE TABLE IF NOT EXISTS users (
    username           TEXT COLLATE "C" PRIMARY KEY,
    user_id            BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    creation_date      TIMESTAMPTZ NOT NULL,
    friendly_name      TEXT,
    email              TEXT COLLATE "C" UNIQUE,
    source             TEXT,
    external_id        TEXT COLLATE "C" UNIQUE,
    encrypted_password BYTEA
);

CREATE TABLE IF NOT EXISTS groups (
    id            TEXT COLLATE "C" PRIMARY KEY,
    description   TEXT,
    creation_date TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    name          TEXT COLLATE "C" PRIMARY KEY,
    creation_date TIMESTAMPTZ NOT NULL,
    statement     JSONB NOT NULL,
    acl           TEXT
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT COLLATE "C" NOT NULL,
    username TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (group_id, username),
    CONSTRAINT group_members_group_fk FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
    CONSTRAINT group_members_user_fk FOREIGN KEY (username) REFERENCES users (username) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS group_members_user_idx ON group_members (username, group_id);

CREATE TABLE IF NOT EXISTS user_policies (
    username    TEXT COLLATE "C" NOT NULL,
    policy_name TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (username, policy_name),
    CONSTRAINT user_policies_user_fk FOREIGN KEY (username) REFERENCES users (username) ON DELETE CASCADE,
    CONSTRAINT user_policies_policy_fk FOREIGN KEY (policy_name) REFERENCES policies (name) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS user_policies_policy_idx ON user_policies (policy_name);

CREATE TABLE IF NOT EXISTS group_policies (
    group_id    TEXT COLLATE "C" NOT NULL,
    policy_name TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (group_id, policy_name),
    CONSTRAINT group_policies_group_fk FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
    CONSTRAINT group_policies_policy_fk FOREIGN KEY (policy_name) REFERENCES policies (name) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS group_policies_policy_idx ON group_policies (policy_name);

CREATE TABLE IF NOT EXISTS credentials (
    access_key_id     TEXT COLLATE "C" PRIMARY KEY,
    username          TEXT COLLATE "C" NOT NULL,
    secret_ciphertext BYTEA NOT NULL,
    creation_date     TIMESTAMPTZ NOT NULL,
    CONSTRAINT credentials_user_fk FOREIGN KEY (username) REFERENCES users (username) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS credentials_user_idx ON credentials (username, access_key_id);

CREATE TABLE IF NOT EXISTS external_principals (
    id       TEXT COLLATE "C" PRIMARY KEY,
    username TEXT COLLATE "C" NOT NULL,
    CONSTRAINT external_principals_user_fk FOREIGN KEY (username) REFERENCES users (username) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS external_principals_user_idx ON external_principals (username, id);

CREATE TABLE IF NOT EXISTS claimed_token_ids (
    token_id   TEXT COLLATE "C" PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS claimed_token_ids_expires_at_idx ON claimed_token_ids (expires_at);
