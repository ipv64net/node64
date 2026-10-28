-- Testumgebung Sonar64 API (s64a*): nur die Spalten, die api_v2.php fuer die Anmeldung braucht. Nicht auf ipv64 einspielen.
CREATE TABLE users (id int NOT NULL PRIMARY KEY, email varchar(255) NOT NULL DEFAULT '', apikey varchar(64) NOT NULL DEFAULT '0',
  account_status varchar(2) NOT NULL DEFAULT '1', user_class int NOT NULL DEFAULT 1, admin int NOT NULL DEFAULT 0);
CREATE TABLE user_class (id int NOT NULL PRIMARY KEY, name varchar(32) NOT NULL);
CREATE TABLE api_keys (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, userid int NOT NULL, token varchar(64) NOT NULL, name varchar(100) NOT NULL DEFAULT '',
  expire varchar(16) NOT NULL DEFAULT '0', used int NOT NULL DEFAULT 0);
CREATE TABLE account_links (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, owner_id int, manager_id int, status int);
INSERT INTO user_class VALUES (1, 'Standard'), (2, 'VIP');
-- 1 aktiv (Account-Key), 2 aktiv (api_keys), 3 inaktiv
INSERT INTO users (id, email, apikey, account_status, user_class) VALUES (1, 'a@test.invalid', 'TestKeyAccountOne000000000000001', '1', 1),
  (2, 'b@test.invalid', '0', '1', 2), (3, 'c@test.invalid', 'TestKeyAccountThree0000000000003', '0', 1);
INSERT INTO api_keys (userid, token, name) VALUES (2, 'TestKeyApiKeysTwo000000000000002', 's64a');
