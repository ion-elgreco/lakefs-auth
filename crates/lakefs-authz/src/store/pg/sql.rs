//! Every statement the PostgreSQL store runs.
//!
//! sqlx 0.9 only accepts `&'static str`, so the SQL lives here as constants and
//! all values are bound. Lists use keyset pagination:
//! `LIKE $prefix ESCAPE '\' AND key > $after ORDER BY key LIMIT $limit`, fetched
//! with one row more than asked for so that `next_offset` can be derived.

pub const INSERT_USER: &str = "INSERT INTO users \
     (username, creation_date, friendly_name, email, source, external_id, encrypted_password) \
     VALUES ($1, $2, $3, $4, $5, $6, $7) \
     RETURNING username, user_id, creation_date, friendly_name, email, source, external_id, encrypted_password";

pub const SELECT_USER: &str = "SELECT username, user_id, creation_date, friendly_name, email, source, external_id, \
     encrypted_password FROM users WHERE username = $1";

pub const SELECT_USER_BY_ID: &str = "SELECT username, user_id, creation_date, friendly_name, email, source, external_id, \
     encrypted_password FROM users WHERE user_id = $1";

pub const SELECT_USER_BY_EMAIL: &str = "SELECT username, user_id, creation_date, friendly_name, email, source, external_id, \
     encrypted_password FROM users WHERE email = $1";

pub const SELECT_USER_BY_EXTERNAL_ID: &str = "SELECT username, user_id, creation_date, friendly_name, email, source, external_id, \
     encrypted_password FROM users WHERE external_id = $1";

pub const LIST_USERS: &str = r"SELECT username, user_id, creation_date, friendly_name, email, source, external_id,
     encrypted_password FROM users
     WHERE username LIKE $1 ESCAPE '\' AND username > $2
     ORDER BY username
     LIMIT $3";

pub const DELETE_USER: &str = "DELETE FROM users WHERE username = $1";

pub const UPDATE_USER_FRIENDLY_NAME: &str = "UPDATE users SET friendly_name = $2 WHERE username = $1";

pub const INSERT_GROUP: &str = "INSERT INTO groups (id, description, creation_date) VALUES ($1, $2, $3) \
     RETURNING id, description, creation_date";

pub const SELECT_GROUP: &str = "SELECT id, description, creation_date FROM groups WHERE id = $1";

pub const DELETE_GROUP: &str = "DELETE FROM groups WHERE id = $1";

pub const LIST_GROUPS: &str = r"SELECT id, description, creation_date FROM groups
     WHERE id LIKE $1 ESCAPE '\' AND id > $2
     ORDER BY id
     LIMIT $3";

pub const INSERT_POLICY: &str = "INSERT INTO policies (name, creation_date, statement, acl) VALUES ($1, $2, $3, $4) \
     RETURNING name, creation_date, statement, acl";

pub const SELECT_POLICY: &str = "SELECT name, creation_date, statement, acl FROM policies WHERE name = $1";

pub const UPDATE_POLICY: &str = "UPDATE policies SET creation_date = $2, statement = $3, acl = $4 WHERE name = $1 \
     RETURNING name, creation_date, statement, acl";

pub const DELETE_POLICY: &str = "DELETE FROM policies WHERE name = $1";

pub const LIST_POLICIES: &str = r"SELECT name, creation_date, statement, acl FROM policies
     WHERE name LIKE $1 ESCAPE '\' AND name > $2
     ORDER BY name
     LIMIT $3";

pub const INSERT_MEMBERSHIP: &str =
    "INSERT INTO group_members (group_id, username) VALUES ($1, $2) ON CONFLICT DO NOTHING";

pub const DELETE_MEMBERSHIP: &str = "DELETE FROM group_members WHERE group_id = $1 AND username = $2";

pub const LIST_GROUP_MEMBERS: &str = r"SELECT u.username, u.user_id, u.creation_date, u.friendly_name, u.email,
            u.source, u.external_id, u.encrypted_password
     FROM group_members m
     JOIN users u ON u.username = m.username
     WHERE m.group_id = $1 AND u.username LIKE $2 ESCAPE '\' AND u.username > $3
     ORDER BY u.username
     LIMIT $4";

pub const LIST_USER_GROUPS: &str = r"SELECT g.id, g.description, g.creation_date
     FROM group_members m
     JOIN groups g ON g.id = m.group_id
     WHERE m.username = $1 AND g.id LIKE $2 ESCAPE '\' AND g.id > $3
     ORDER BY g.id
     LIMIT $4";

pub const INSERT_USER_POLICY: &str =
    "INSERT INTO user_policies (username, policy_name) VALUES ($1, $2) ON CONFLICT DO NOTHING";

pub const DELETE_USER_POLICY: &str = "DELETE FROM user_policies WHERE username = $1 AND policy_name = $2";

pub const LIST_USER_POLICIES: &str = r"SELECT p.name, p.creation_date, p.statement, p.acl
     FROM user_policies a
     JOIN policies p ON p.name = a.policy_name
     WHERE a.username = $1 AND p.name LIKE $2 ESCAPE '\' AND p.name > $3
     ORDER BY p.name
     LIMIT $4";

/// Direct attachments and group attachments in one pass. lakeFS asks for this
/// on every authorization decision, so the query is driven from the user's own
/// attachment rows and touches only those, never the whole policies table. The
/// `UNION` removes the duplicates a user gets through several groups.
pub const LIST_EFFECTIVE_USER_POLICIES: &str = r"SELECT p.name, p.creation_date, p.statement, p.acl
     FROM policies p
     JOIN (
         SELECT policy_name FROM user_policies WHERE username = $1
         UNION
         SELECT gp.policy_name FROM group_policies gp
         JOIN group_members gm ON gm.group_id = gp.group_id
         WHERE gm.username = $1
     ) a ON a.policy_name = p.name
     WHERE p.name LIKE $2 ESCAPE '\' AND p.name > $3
     ORDER BY p.name
     LIMIT $4";

pub const INSERT_GROUP_POLICY: &str =
    "INSERT INTO group_policies (group_id, policy_name) VALUES ($1, $2) ON CONFLICT DO NOTHING";

pub const DELETE_GROUP_POLICY: &str = "DELETE FROM group_policies WHERE group_id = $1 AND policy_name = $2";

pub const LIST_GROUP_POLICIES: &str = r"SELECT p.name, p.creation_date, p.statement, p.acl
     FROM group_policies a
     JOIN policies p ON p.name = a.policy_name
     WHERE a.group_id = $1 AND p.name LIKE $2 ESCAPE '\' AND p.name > $3
     ORDER BY p.name
     LIMIT $4";

pub const INSERT_CREDENTIAL: &str = "WITH inserted AS (
         INSERT INTO credentials (access_key_id, username, secret_ciphertext, creation_date)
         VALUES ($1, $2, $3, $4)
         RETURNING access_key_id, username, secret_ciphertext, creation_date
     )
     SELECT i.access_key_id, i.username, u.user_id, i.secret_ciphertext, i.creation_date
     FROM inserted i JOIN users u ON u.username = i.username";

pub const SELECT_CREDENTIAL: &str = "SELECT c.access_key_id, c.username, u.user_id, c.secret_ciphertext, c.creation_date \
     FROM credentials c JOIN users u ON u.username = c.username WHERE c.access_key_id = $1";

pub const SELECT_USER_CREDENTIAL: &str = "SELECT c.access_key_id, c.username, u.user_id, c.secret_ciphertext, c.creation_date \
     FROM credentials c JOIN users u ON u.username = c.username \
     WHERE c.access_key_id = $1 AND c.username = $2";

pub const DELETE_CREDENTIAL: &str = "DELETE FROM credentials WHERE access_key_id = $1 AND username = $2";

pub const LIST_USER_CREDENTIALS: &str = r"SELECT c.access_key_id, c.username, u.user_id, c.secret_ciphertext,
            c.creation_date
     FROM credentials c
     JOIN users u ON u.username = c.username
     WHERE c.username = $1 AND c.access_key_id LIKE $2 ESCAPE '\' AND c.access_key_id > $3
     ORDER BY c.access_key_id
     LIMIT $4";

pub const INSERT_EXTERNAL_PRINCIPAL: &str = "INSERT INTO external_principals (id, username) VALUES ($1, $2)";

pub const DELETE_EXTERNAL_PRINCIPAL: &str = "DELETE FROM external_principals WHERE id = $1 AND username = $2";

pub const SELECT_EXTERNAL_PRINCIPAL: &str = "SELECT id, username FROM external_principals WHERE id = $1";

pub const LIST_USER_EXTERNAL_PRINCIPALS: &str = r"SELECT id, username FROM external_principals
     WHERE username = $1 AND id LIKE $2 ESCAPE '\' AND id > $3
     ORDER BY id
     LIMIT $4";

pub const INSERT_TOKEN_ID: &str = "INSERT INTO claimed_token_ids (token_id, expires_at) VALUES ($1, $2)";

pub const DELETE_EXPIRED_TOKEN_IDS: &str = "DELETE FROM claimed_token_ids WHERE expires_at <= $1";

pub const SELECT_USER_EXISTS: &str = "SELECT 1 FROM users WHERE username = $1";

pub const SELECT_GROUP_EXISTS: &str = "SELECT 1 FROM groups WHERE id = $1";

pub const PING: &str = "SELECT 1";

// The bootstrap inserts name their conflict target. Without one PostgreSQL
// would also swallow a violation of another unique index, so a user whose
// email or external id belongs to a different row would be skipped in silence.
pub const BOOTSTRAP_INSERT_POLICY: &str = "INSERT INTO policies (name, creation_date, statement, acl) \
     VALUES ($1, $2, $3, $4) ON CONFLICT (name) DO NOTHING";

pub const BOOTSTRAP_INSERT_GROUP: &str =
    "INSERT INTO groups (id, description, creation_date) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING";

pub const BOOTSTRAP_INSERT_USER: &str = "INSERT INTO users \
     (username, creation_date, friendly_name, email, source, external_id, encrypted_password) \
     VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (username) DO NOTHING";

pub const BOOTSTRAP_INSERT_CREDENTIAL: &str = "INSERT INTO credentials (access_key_id, username, secret_ciphertext, creation_date) \
     VALUES ($1, $2, $3, $4) ON CONFLICT (access_key_id) DO NOTHING";
