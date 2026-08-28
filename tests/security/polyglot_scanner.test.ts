import { describe, expect, it } from "vitest";
import { POLYGLOT_SECURITY_RULES } from "@/agents/polyglot/rules";

describe("🌐 Polyglot Security Scanner: Cobertura Multilinguagem", () => {
  describe("1. Regras Python (Django / FastAPI / Flask)", () => {
    const pyRules = POLYGLOT_SECURITY_RULES.filter((r) => r.language === "python");

    it("detecta injeção SQL em f-strings no Python (PY-01)", () => {
      const rule = pyRules.find((r) => r.id === "PY-01")!;
      const vulnerableCode = `cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")`;
      expect(rule.regex.test(vulnerableCode)).toBe(true);
    });

    it("detecta desserialização insegura com pickle.loads (PY-02)", () => {
      const rule = pyRules.find((r) => r.id === "PY-02")!;
      const vulnerableCode = `data = pickle.loads(raw_untrusted_data)`;
      expect(rule.regex.test(vulnerableCode)).toBe(true);
    });

    it("detecta subprocess com shell=True (PY-03)", () => {
      const rule = pyRules.find((r) => r.id === "PY-03")!;
      const vulnerableCode = `subprocess.run(user_cmd, shell=True)`;
      expect(rule.regex.test(vulnerableCode)).toBe(true);
    });
  });

  describe("2. Regras PHP (Laravel / WordPress)", () => {
    const phpRules = POLYGLOT_SECURITY_RULES.filter((r) => r.language === "php");

    it("detecta injeção SQL em queries mysqli com concatenação direta (PHP-01)", () => {
      const rule = phpRules.find((r) => r.id === "PHP-01")!;
      const vulnerableCode = `$result = mysqli_query($conn, "SELECT * FROM items WHERE id = " . $_GET['id']);`;
      expect(rule.regex.test(vulnerableCode)).toBe(true);
    });

    it("detecta desserialização com unserialize() de inputs (PHP-02)", () => {
      const rule = phpRules.find((r) => r.id === "PHP-02")!;
      const vulnerableCode = `$user = unserialize($_COOKIE['session_data']);`;
      expect(rule.regex.test(vulnerableCode)).toBe(true);
    });
  });

  describe("3. Regras Java (Spring Boot / JPA / JDBC)", () => {
    const javaRules = POLYGLOT_SECURITY_RULES.filter((r) => r.language === "java");

    it("detecta injeção SQL em createQuery com concatenação (JAVA-01)", () => {
      const rule = javaRules.find((r) => r.id === "JAVA-01")!;
      const vulnerableCode = `Query q = em.createQuery("SELECT u FROM User u WHERE u.name = '" + inputName);`;
      expect(rule.regex.test(vulnerableCode)).toBe(true);
    });
  });

  describe("4. Regras C# (.NET / Entity Framework)", () => {
    const csRules = POLYGLOT_SECURITY_RULES.filter((r) => r.language === "csharp");

    it("detecta interpolação insegura em FromSqlRaw (CS-01)", () => {
      const rule = csRules.find((r) => r.id === "CS-01")!;
      const vulnerableCode = `var users = context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Email = '{email}'");`;
      expect(rule.regex.test(vulnerableCode)).toBe(true);
    });
  });

  describe("5. Regras Go (Golang / database/sql)", () => {
    const goRules = POLYGLOT_SECURITY_RULES.filter((r) => r.language === "go");

    it("detecta injeção SQL via fmt.Sprintf em db.Query (GO-01)", () => {
      const rule = goRules.find((r) => r.id === "GO-01")!;
      const vulnerableCode = `rows, err := db.Query(fmt.Sprintf("SELECT * FROM products WHERE id = '%s'", prodId))`;
      expect(rule.regex.test(vulnerableCode)).toBe(true);
    });
  });
});
