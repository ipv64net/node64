-- PROXY64 1.54: PROXY-Protokoll zum Ziel je TCP-Stream ("" = aus, v1, v2; #52), wie advanced.proxy_protocol bei "TLS durchreichen"
ALTER TABLE cdn_streams ADD COLUMN proxy_protocol TEXT NOT NULL DEFAULT '';
