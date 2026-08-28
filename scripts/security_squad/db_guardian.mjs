import fs from "node:fs";
import path from "node:path";

/**
 * Agente DB Guardian & SQL RLS Auditor
 * Analisa arquivos de migração e schemas PostgreSQL em busca de falhas em políticas RLS.
 */

const SQL_RULES = [
  {
    name: "Tabela sem ENABLE ROW LEVEL SECURITY",
    check: (sql) => {
      const creates = [...sql.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_."]+)/gi)];
      const rlsEnables = [...sql.matchAll(/ALTER\s+TABLE\s+([a-zA-Z0-9_."]+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi)];
      
      const enabledTables = new Set(rlsEnables.map(m => m[1].replace(/["']/g, "").toLowerCase()));
      const unshielded = [];

      for (const match of creates) {
        const table = match[1].replace(/["']/g, "").toLowerCase();
        // Ignora schemas internos
        if (!table.startsWith("pg_") && !enabledTables.has(table) && !enabledTables.has(`public.${table}`)) {
          unshielded.push(table);
        }
      }
      return unshielded;
    },
  },
  {
    name: "Concessão insegura GRANT ALL TO anon",
    check: (sql) => {
      const dangerousGrants = [...sql.matchAll(/GRANT\s+ALL\s+ON\s+TABLE\s+([a-zA-Z0-9_."]+)\s+TO\s+anon/gi)];
      return dangerousGrants.map(m => m[1]);
    },
  },
];

export function runDbGuardianAudit(rootDir = ".") {
  const migrationsDir = path.join(rootDir, "supabase", "migrations");
  const sqlFiles = [];

  if (fs.existsSync(migrationsDir)) {
    const files = fs.readdirSync(migrationsDir);
    for (const file of files) {
      if (file.endsWith(".sql")) {
        sqlFiles.push(path.join(migrationsDir, file));
      }
    }
  }

  const findings = [];

  for (const file of sqlFiles) {
    const content = fs.readFileSync(file, "utf-8");

    for (const rule of SQL_RULES) {
      const violations = rule.check(content);
      if (violations && violations.length > 0) {
        findings.push({
          file: path.relative(rootDir, file),
          rule: rule.name,
          targets: violations,
        });
      }
    }
  }

  return {
    agent: "DB Guardian (SQL RLS Auditor)",
    status: findings.length === 0 ? "PASSED" : "FAILED",
    migrationsScanned: sqlFiles.length,
    findings,
  };
}

if (process.argv[1] === import.meta.filename) {
  console.log("🛡️ Executando DB Guardian (SQL RLS Auditor)...");
  const result = runDbGuardianAudit();
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.status === "PASSED" ? 0 : 1);
}
