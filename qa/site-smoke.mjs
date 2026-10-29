import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, copyFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const browsers = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url));
const site = await mkdtemp(join(tmpdir(), 'harness-site-'));
await mkdir(join(site, 'py'));
await mkdir(join(site, 'examples'));
await copyFile(join(root, 'site/index.html'), join(site, 'index.html'));
for (const name of ['__init__', 'model', 'rules', 'ci', 'engine', 'report']) {
  await copyFile(join(root, `src/harness_doctor/${name}.py`), join(site, `py/${name}.py`));
}
for (const [from, to] of [['bad/deploy.yaml', 'bad.yaml'], ['good/deploy.yaml', 'good.yaml'], ['bad/workflow.yml', 'workflow.yml'], ['bad/Jenkinsfile', 'Jenkinsfile']]) {
  await copyFile(join(root, `examples/${from}`), join(site, `examples/${to}`));
}
const server = createServer(async (req, res) => {
  const path = resolve(site, '.' + decodeURIComponent(req.url === '/' ? '/index.html' : req.url));
  if (!path.startsWith(site + '/')) { res.writeHead(403).end(); return; }
  try {
    res.setHeader('Content-Type', path.endsWith('.html') ? 'text/html' : 'text/plain');
    res.end(await readFile(path));
  } catch { res.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const url = `http://127.0.0.1:${server.address().port}/`;
try {
  for (const name of (process.env.BROWSERS || 'chromium').split(',')) {
    const browser = await browsers[name].launch();
    try {
      for (const width of [375, 1440]) {
        const context = await browser.newContext({ viewport: { width, height: 900 }, reducedMotion: 'reduce' });
        const page = await context.newPage();
        const requests = [], errors = [], sizes = [];
        page.on('request', r => requests.push(r.url()));
        page.on('pageerror', e => errors.push(String(e)));
        page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
        page.on('response', r => sizes.push(r.finished().then(() => r.request().sizes()).then(s => s.responseBodySize).catch(() => 0)));
        await page.goto(url);
        await page.waitForFunction(() => document.querySelector('#src').value.includes('pipeline:'));
        await page.waitForTimeout(500);
        assert.equal(requests.filter(u => /pyodide|\.wasm(?:$|\?)/.test(u)).length, 0, 'runtime fetched before activation');
        assert.equal(await page.locator('#run-checks').isVisible(), true);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
        const initialBytes = (await Promise.all(sizes)).reduce((a, b) => a + b, 0);
        await page.locator('[data-ex="bad"]').click();
        await page.waitForFunction(() => window.__HD_READY__ === true, null, { timeout: 120000 });
        await page.waitForFunction(() => document.querySelector('#out').textContent.includes('HD001'));
        assert.match(await page.locator('#summary').innerText(), /2 errors/);
        await page.locator('[data-ex="good"]').click();
        await page.waitForFunction(() => document.querySelector('#summary').textContent.includes('No findings'));
        await page.locator('[data-ex="workflow"]').click();
        await page.waitForFunction(() => document.querySelector('#out').textContent.includes('GA003'));
        await page.locator('[data-ex="jenkins"]').click();
        await page.waitForFunction(() => document.querySelector('#out').textContent.includes('JK001'));
        assert.equal(await page.locator('#rules-body tr').count(), 25);
        assert.deepEqual(errors, []);
        const totalBytes = (await Promise.all(sizes)).reduce((a, b) => a + b, 0);
        console.log(JSON.stringify({ browser: name, width, initialResponseBodyBytes: initialBytes, activatedResponseBodyBytes: totalBytes, checks: 'bad/clean/Actions/Jenkins actual Python engine passed' }));
        await context.close();
      }
      const offline = await browser.newContext({ javaScriptEnabled: false });
      const page = await offline.newPage();
      await page.goto(url);
      assert.match(await page.locator('noscript').innerText(), /JavaScript is off/);
      assert.equal(await page.locator('#run-checks').isVisible(), false);
      await offline.close();
      const retry = await browser.newContext();
      const retryPage = await retry.newPage();
      await retryPage.route('**/pyodide.js', route => route.abort(), { times: 1 });
      await retryPage.goto(url);
      await retryPage.locator('#run-checks').click();
      await retryPage.waitForFunction(() => document.querySelector('#run-checks').textContent === 'Retry checks');
      assert.match(await retryPage.locator('#out').innerText(), /did not load/);
      await retryPage.locator('#run-checks').click();
      await retryPage.waitForFunction(() => window.__HD_READY__ === true, null, { timeout: 120000 });
      assert.match(await retryPage.locator('#out').innerText(), /HD001/);
      await retry.close();
    } finally { await browser.close(); }
  }
} finally {
  await new Promise(resolve => server.close(resolve));
  await rm(site, { recursive: true, force: true });
}
