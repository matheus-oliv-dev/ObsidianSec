async function checkGoogle() {
  const res = await fetch("https://www.google.com.br", {
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    }
  });

  console.log("Status:", res.status);
  console.log("Headers de google.com.br:");
  for (const [k, v] of res.headers.entries()) {
    console.log(`  ${k}: ${v}`);
  }
}

checkGoogle();
