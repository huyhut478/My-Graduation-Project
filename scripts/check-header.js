import http from 'http';

const opts = {
  hostname: 'localhost',
  port: 3000,
  path: '/',
  method: 'GET',
  timeout: 5000
};

const req = http.request(opts, (res) => {
  let data = '';
  res.setEncoding('utf8');
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    const hasHeader = data.includes('<header>');
    const hasSettingsBtn = data.includes('id="settings-btn"');
    const hasDarkToggle = data.includes('id="dark-mode-toggle"');

    console.log('header tag present:', hasHeader);
    console.log('settings button present:', hasSettingsBtn);
    console.log('dark-mode toggle present:', hasDarkToggle);

    if (hasHeader && hasSettingsBtn && hasDarkToggle) {
      console.log('\nEverything looks OK — header and settings controls are present.');
      process.exit(0);
    }

    console.error('\nProblem detected: missing elements in homepage HTML.');
    process.exit(2);
  });
});

req.on('error', (err) => {
  console.error('Failed to fetch http://localhost:3000 :', err.message);
  process.exit(3);
});

req.end();
