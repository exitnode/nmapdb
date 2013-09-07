/*
 * nmapdb - Parse nmap's XML output files and insert them into an SQLite database
 * Copyright (c) 2012 Patroklos Argyroudis <argp at domain census-labs.com>
 */

CREATE TABLE IF NOT EXISTS hosts (
    ip          VARCHAR(16) NOT NULL,
    mac         VARCHAR(18),
    hostname    VARCHAR(129),
    protocol    VARCHAR(5) DEFAULT 'ipv4',
    os_name     TEXT,
    os_family   TEXT,
    os_accuracy INTEGER,
    os_gen      TEXT,
    last_update TIMESTAMP,
    state       VARCHAR(8) DEFAULT 'down',
    mac_vendor  TEXT,
    whois       TEXT,
    scan_id     TIMESTAMP,
    PRIMARY KEY (ip, scan_id)
);

CREATE TABLE IF NOT EXISTS ports (
    ip          VARCHAR(16) NOT NULL,
    port        INTEGER NOT NULL,
    protocol    VARCHAR(4) NOT NULL,
    name        VARCHAR(33),
    state       VARCHAR(33) DEFAULT 'closed',
    service     TEXT,
    info        TEXT,
    scan_id     TIMESTAMP,
    PRIMARY KEY (ip, port, protocol, scan_id),
    CONSTRAINT fk_ports_hosts FOREIGN KEY (ip) REFERENCES hosts(ip) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scaninfo (
    scan_id     TIMESTAMP NOT NULL,
    nmap_args   TEXT,
    type 	VARCHAR(4),
    protocol    VARCHAR(4),
    numservices INTEGER,
    start	TIMESTAMP,
    startstr	VARCHAR(33),
    end		TIMESTAMP,
    endstr	VARCHAR(33),
    elapsed	INTEGER,
    summary     TEXT,
    PRIMARY KEY (scan_id)
);

CREATE TRIGGER IF NOT EXISTS fki_ports_hosts_ip
BEFORE INSERT ON ports
FOR EACH ROW BEGIN
    SELECT CASE
        WHEN ((SELECT ip FROM hosts WHERE ip = NEW.ip) IS NULL)
        THEN RAISE(ABORT, 'insert on table "ports" violates foreign key constraint "fk_ports_hosts"')
    END;
END;

CREATE TRIGGER IF NOT EXISTS fku_ports_hosts_ip
BEFORE UPDATE ON ports
FOR EACH ROW BEGIN
    SELECT CASE
        WHEN ((SELECT ip FROM hosts WHERE ip = NEW.ip) IS NULL)
        THEN RAISE(ABORT, 'update on table "ports" violates foreign key constraint "fk_ports_hosts"')
    END;
END;

CREATE TRIGGER IF NOT EXISTS fkd_ports_hosts_ip
BEFORE DELETE ON hosts
FOR EACH ROW BEGIN
    DELETE from ports WHERE ip = OLD.ip;
END;

/* EOF */
