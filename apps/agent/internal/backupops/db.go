package backupops

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ppanel/ppanel/apps/agent/internal/jobs"
)

// PgInventoryQuery returns exact row counts (T rows, ≤ 200 tables) and
// constraint names (C rows, ≤ 1000) in ONE read-only statement (the session
// also runs with default_transaction_read_only=on).
const PgInventoryQuery = `(select 'T', n.nspname || '.' || c.relname,
  (xpath('/row/c/text()', query_to_xml(format('select count(*) as c from %I.%I', n.nspname, c.relname), false, true, '')))[1]::text
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where c.relkind in ('r', 'p') and n.nspname not in ('pg_catalog', 'information_schema') and n.nspname not like 'pg_toast%'
  order by 2 limit 200)
union all
(select 'C', n.nspname || '.' || cl.relname || ':' || co.conname, ''
  from pg_constraint co join pg_class cl on cl.oid = co.conrelid join pg_namespace n on n.oid = cl.relnamespace
  where n.nspname not in ('pg_catalog', 'information_schema')
  order by 2 limit 1000)`

// MysqlInventoryQuery lists base tables and constraint names of the current DB.
const MysqlInventoryQuery = `select * from (select 'T', table_name, '' from information_schema.tables
  where table_schema = database() and table_type = 'BASE TABLE' order by table_name limit 200) t
union all
select * from (select 'C', concat(table_name, ':', constraint_name), '' from information_schema.table_constraints
  where table_schema = database() order by 2 limit 1000) c`

var mysqlIdentRe = regexp.MustCompile(`^[A-Za-z0-9_$]{1,64}$`)

// MysqlCountQuery builds the exact count query for validated table names.
func MysqlCountQuery(tables []string) string {
	parts := make([]string, 0, len(tables))
	for _, t := range tables {
		if mysqlIdentRe.MatchString(t) {
			parts = append(parts, fmt.Sprintf("select '%s', count(*) from `%s`", t, t))
		}
	}
	return strings.Join(parts, " union all ")
}

// clientArgs builds the psql / mysql argv for a query or a dump load.
func clientArgs(c dbConn, query, file string) (entry []string, args []string) {
	if c.Type == "mysql" {
		args = []string{"--batch", "--skip-column-names", "--host=" + c.Host, "--port=" + fmtPort(c.Port),
			"--user=" + c.User, "--database=" + c.Database}
		if file != "" {
			return []string{"mysql"}, append(args, "-e", "source "+file)
		}
		return []string{"mysql"}, append(args, "--init-command=SET SESSION TRANSACTION READ ONLY", "-e", query)
	}
	args = []string{"-X", "--no-password", "--host=" + c.Host, "--port=" + fmtPort(c.Port), "--username=" + c.User, "--dbname=" + c.Database}
	if file != "" {
		return []string{"psql"}, append(args, "-q", "-v", "ON_ERROR_STOP=1", "-f", file)
	}
	return []string{"psql"}, append(args, "-A", "-t", "-F", "|", "-c", query)
}

func (s *session) clientSpec(role string, c dbConn, entry, args []string, env ...string) HelperSpec {
	sp := HelperSpec{Role: role, App: c.App, RunLabel: c.Label, Image: s.image, Entrypoint: entry, Cmd: args,
		Env: append([]string{c.passwordEnv()}, env...), Network: c.Network, Hostname: s.m.o.Hostname}
	return sp
}

// parseInventory parses "K<sep>name<sep>value" rows.
func parseInventory(out, sep string) (tables []TableCount, cons []string, err error) {
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.SplitN(line, sep, 3)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "T":
			v := ""
			if len(f) == 3 {
				v = strings.TrimSpace(f[2])
			}
			n, perr := strconv.ParseInt(v, 10, 64)
			if v == "" {
				n, perr = -1, nil // count still to be taken (mysql step 2)
			}
			if perr != nil {
				return nil, nil, fmt.Errorf("bad row count for %s", f[1])
			}
			tables = append(tables, TableCount{Name: f[1], Rows: n})
		case "C":
			cons = append(cons, f[1])
		}
	}
	if tables == nil {
		tables = []TableCount{}
	}
	if cons == nil {
		cons = []string{}
	}
	return tables, cons, nil
}

// queryDB returns exact per-table row counts and constraint names (helper
// psql / mysql client, read-only session).
func (s *session) queryDB(c dbConn) ([]TableCount, []string, error) {
	run := func(q string) (string, error) {
		entry, args := clientArgs(c, q, "")
		var env []string
		if c.Type == "postgres" {
			env = []string{"PGOPTIONS=-c default_transaction_read_only=on"}
		}
		res, err := s.runHelper(s.clientSpec("query", c, entry, args, env...), nil)
		if err != nil {
			return "", s.dockerErr("query helper", err)
		}
		if res.ExitCode != 0 {
			return "", jerr(CodeDumpFailed, "%s query failed (exit %d): %s", c.Type, res.ExitCode, truncate(strings.TrimSpace(string(res.Stderr)), 1000))
		}
		return string(res.Stdout), nil
	}
	if c.Type == "postgres" {
		out, err := run(PgInventoryQuery)
		if err != nil {
			return nil, nil, err
		}
		return parseInventory(out, "|")
	}
	out, err := run(MysqlInventoryQuery)
	if err != nil {
		return nil, nil, err
	}
	tables, cons, err := parseInventory(out, "\t")
	if err != nil || len(tables) == 0 {
		return tables, cons, err
	}
	names := make([]string, 0, len(tables))
	for _, t := range tables {
		names = append(names, t.Name)
	}
	q := MysqlCountQuery(names)
	if q == "" {
		return tables, cons, nil
	}
	out, err = run(q)
	if err != nil {
		return nil, nil, err
	}
	counts, _, err := parseInventory(prefixRows(out, "T\t"), "\t")
	if err != nil {
		return nil, nil, err
	}
	return counts, cons, nil
}

func prefixRows(out, p string) string {
	var b strings.Builder
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			b.WriteString(p + l + "\n")
		}
	}
	return b.String()
}

// waitReady polls the DB with the client helper until it accepts a session.
func (s *session) waitReady(c dbConn) error {
	deadline := time.Now().Add(s.m.o.ScratchReadyTimeout)
	var entry, args []string
	if c.Type == "mysql" {
		entry, args = clientArgs(c, "select 1", "")
	} else {
		entry = []string{"pg_isready"}
		args = []string{"--host=" + c.Host, "--port=" + fmtPort(c.Port), "--username=" + c.User, "--dbname=" + c.Database, "--timeout=3"}
	}
	last := ""
	for {
		res, err := s.runHelper(s.clientSpec("ready", c, entry, args), nil)
		if err != nil {
			return s.dockerErr("readiness helper", err)
		}
		if res.ExitCode == 0 {
			return nil
		}
		last = truncate(strings.TrimSpace(string(res.Stderr)+" "+string(res.Stdout)), 300)
		if time.Now().After(deadline) {
			return jerr(CodeRestoreFailed, "database %s not ready within %s: %s", c.Host, s.m.o.ScratchReadyTimeout, last)
		}
		select {
		case <-s.ctx.Done():
			return abortedErr(s.ctx, "readiness wait")
		case <-time.After(s.m.o.ReadyInterval):
		}
	}
}

// loadDump restores the snapshot's dump into c: helper A (restic dump →
// /work/<file>) hands the file to a not-yet-started client helper B via the
// archive API; B runs psql -f / mysql -e "source …". No shell anywhere.
func (s *session) loadDump(snap string, t Target, c dbConn) (sha string, size int64, err error) {
	file := t.DumpFile()
	dst := path.Join(HelperWorkDir, file)
	var loadErr error
	sha, size, _, err = s.fetchDump(snap, c.App, c.Label, file, nil, func(a *helperRun) error {
		entry, args := clientArgs(c, "", dst)
		spec := s.clientSpec("load", c, entry, args)
		spec.Writable = true
		b, err := createHelper(s.ctx, s.m.o.Engine, spec, s.log)
		if err != nil {
			return s.dockerErr("create load helper", err)
		}
		defer b.remove()
		rc, err := a.archive(s.ctx, dst)
		if err != nil {
			return s.dockerErr("read dump", err)
		}
		err = s.m.o.Engine.PutArchive(s.ctx, b.name, HelperWorkDir, rc)
		rc.Close()
		if err != nil {
			return s.dockerErr("hand dump to load helper", err)
		}
		res, err := b.startWait(s.ctx)
		if err != nil {
			if s.ctx.Err() != nil {
				return abortedErr(s.ctx, "dump load")
			}
			return s.dockerErr("load helper", err)
		}
		if res.ExitCode != 0 {
			loadErr = jerr(CodeRestoreFailed, "%s load into %s failed (exit %d): %s", c.Type, c.Host, res.ExitCode,
				truncate(strings.TrimSpace(string(res.Stderr)), 1500))
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	return sha, size, loadErr
}

var createTableRe = regexp.MustCompile(`(?i)^CREATE TABLE (?:IF NOT EXISTS )?([A-Za-z0-9_."` + "`" + `$]{1,130})`)

// tableScanner collects CREATE TABLE names from dump lines (dry-run listing).
func tableScanner(dst *[]string) func(string) {
	return func(line string) {
		if len(*dst) >= MaxTables {
			return
		}
		if m := createTableRe.FindStringSubmatch(line); m != nil {
			*dst = append(*dst, strings.NewReplacer(`"`, "", "`", "").Replace(m[1]))
		}
	}
}

var _ = jobs.HandlerFailed
