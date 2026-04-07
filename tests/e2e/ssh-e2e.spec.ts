import { test, expect } from '@playwright/test';
import { execSync, spawn } from 'child_process';

// Black-box E2E: walk the full user flow from enrollment to SSH session.
// No pre-existing config, no API shortcuts — everything through the webapp UI.

const AGENT_BIN = 'D:\\devolutions-gateway-quic-agent-tunnel\\target\\release\\devolutions-agent.exe';
const AGENT_CONFIG_DIR = 'C:\\ProgramData\\Devolutions\\Agent-E2E-BlackBox';

test('Full user flow: enroll agent from UI, SSH through tunnel', async ({ page }) => {
  test.setTimeout(180_000);

  // Clean up any previous agent config.
  try { execSync(`rmdir /s /q "${AGENT_CONFIG_DIR}"`, { stdio: 'ignore' }); } catch {}
  execSync(`mkdir "${AGENT_CONFIG_DIR}"`, { stdio: 'ignore' });

  // --- Step 1: Navigate to Agents page ---
  await page.goto('/jet/webapp/client');
  await page.waitForLoadState('networkidle');
  await page.locator('text=Agents').first().click();
  await page.waitForTimeout(2000);

  // --- Step 2: Click Enroll Agent, fill form, generate enrollment string ---
  const enrollBtn = page.locator('button:has-text("Enroll"), button:has-text("enrollment")').first();
  await enrollBtn.click();
  await page.waitForTimeout(1000);

  // Fill the enrollment form fields.
  const gatewayUrlInput = page.locator('input[placeholder*="Gateway"], input[placeholder*="URL"], #apiBaseUrl').first();
  if (await gatewayUrlInput.isVisible({ timeout: 2000 }).catch(() => false)) {
    await gatewayUrlInput.clear();
    await gatewayUrlInput.fill('http://127.0.0.1:7272');
  }

  // Set QUIC host to 127.0.0.1 (avoid localhost → IPv6 resolution).
  const quicHostInput = page.locator('input[placeholder*="QUIC"], input[placeholder*="Host"], #quicHost').first();
  if (await quicHostInput.isVisible({ timeout: 2000 }).catch(() => false)) {
    await quicHostInput.clear();
    await quicHostInput.fill('127.0.0.1');
  }

  // Click Generate.
  await page.locator('button:has-text("Generate")').first().click();
  await page.waitForTimeout(3000);

  // --- Step 3: Extract the enrollment string from the page ---
  await page.screenshot({ path: 'test-results/01-enrollment-generated.png' });

  const enrollmentText = await page.locator('code, .enrollment-string-block, pre').first().innerText();
  expect(enrollmentText).toContain('dgw-enroll:v1:');
  const enrollmentString = enrollmentText.trim();
  console.log('Enrollment string:', enrollmentString.slice(0, 60) + '...');

  // --- Step 4: Enroll agent, then start it (two-step: enroll writes config, run starts tunnel) ---
  // Step 4a: Enroll (writes certs + config to default path).
  try {
    const enrollOutput = execSync(
      `"${AGENT_BIN}" up --enrollment-string "${enrollmentString}" --name e2e-blackbox-agent --advertise-subnets 127.0.0.0/8`,
      { stdio: 'pipe', timeout: 30000 },
    );
    console.log('Enroll output:', enrollOutput.toString());
  } catch (e: any) {
    console.error('Enroll failed:', e.stderr?.toString() || e.message);
    throw e;
  }

  // Step 4b: Start agent (reads config from default path, connects to gateway).
  const agentProc = spawn(AGENT_BIN, ['run'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  });

  let agentStderr = '';
  agentProc.stderr?.on('data', (d: Buffer) => { agentStderr += d.toString(); });
  agentProc.stdout?.on('data', (d: Buffer) => { console.log('[agent]', d.toString().trim()); });

  // Wait for agent to connect.
  await page.waitForTimeout(12000);

  console.log('Agent stderr:', agentStderr.slice(0, 500));
  console.log('Agent alive:', !agentProc.killed, 'pid:', agentProc.pid);
  expect(agentProc.pid).toBeTruthy();

  // --- Step 5: Close enrollment modal, refresh Agents page, verify agent appears ---
  // Navigate away and back to refresh the agent list.
  await page.goto('/jet/webapp/client');
  await page.waitForLoadState('networkidle');
  await page.locator('text=Agents').first().click();
  await page.waitForTimeout(3000);
  // Click Refresh if available.
  const refreshBtn = page.locator('button:has-text("Refresh")').first();
  if (await refreshBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
    await refreshBtn.click();
    await page.waitForTimeout(3000);
  }

  const agentsPageText = await page.locator('body').innerText();
  await page.screenshot({ path: 'test-results/02-agent-connected.png' });
  console.log('Agents page:', agentsPageText.slice(0, 300));
  expect(agentsPageText).toContain('ONLINE');

  // --- Step 6: Create SSH session through the tunnel ---
  await page.goto('/jet/webapp/client');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(2000);

  // Select SSH protocol.
  await page.locator('#protocol').click();
  await page.locator('p-select-option span:text-is("SSH"), li:has-text("SSH")').first().click();
  await page.waitForTimeout(500);

  // Fill SSH form — Docker container on 127.0.0.1:22 (testuser/testpass).
  await page.locator('p-autocomplete input[role="combobox"]').first().fill('127.0.0.1');
  await page.locator('#username').fill('testuser');
  await page.locator('input[placeholder="Enter Password"], p-password input').first().fill('testpass');

  // Connect.
  await page.locator('button:has-text("Connect Session")').click();

  // --- Step 7: Wait for terminal, accept host key, verify commands ---
  const terminal = page.locator('.xterm');
  await terminal.waitFor({ state: 'visible', timeout: 30000 });
  await page.waitForTimeout(3000);
  await terminal.click();

  const xtermRows = page.locator('.xterm-rows');
  let text = await xtermRows.innerText();

  // Accept host key if prompted.
  if (text.includes('yes/no')) {
    await page.keyboard.type('yes');
    await page.keyboard.press('Enter');
  }

  // Wait for shell prompt.
  for (let i = 0; i < 20; i++) {
    await page.waitForTimeout(1000);
    text = await xtermRows.innerText();
    if (text.includes('$') || text.includes('#')) break;
  }

  await page.screenshot({ path: 'test-results/03-ssh-connected.png' });
  expect(text).toMatch(/[$#]/);

  // Run ls.
  await page.keyboard.type('ls');
  await page.keyboard.press('Enter');
  await page.waitForTimeout(2000);

  // Run echo hello.
  await page.keyboard.type('echo "hello"');
  await page.keyboard.press('Enter');
  await page.waitForTimeout(2000);

  text = await xtermRows.innerText();
  await page.screenshot({ path: 'test-results/04-commands-executed.png' });
  console.log('Terminal output:', text.slice(-200));
  expect(text).toContain('hello');

  // --- Cleanup ---
  agentProc.kill();
});
