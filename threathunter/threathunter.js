import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync, spawnSync } from 'child_process';
import readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';
import OpenAI from 'openai';

const CONFIG_PATH = path.resolve('./hunter_config.json');
const TOOLS_DIR = path.join(os.tmpdir(), 'ThreatHunter_Sysinternals');
const MAX_OUTPUT_CHARS = 12000;

const SYSINTERNALS_TOOLS = [
	'autorunsc64.exe',
	'sigcheck64.exe',
	'tcpvcon64.exe',
	'listdlls64.exe',
	'handle64.exe',
	'pslist64.exe',
	'strings64.exe'
];

function loadConfig() {
	if (!fs.existsSync(CONFIG_PATH)) {
		console.error(`[!] Configuration file not found at: ${CONFIG_PATH}`);
		process.exit(1);
	}
	return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
}

function ensureElevation() {
	try {
		execSync('net session', { stdio: 'ignore' });
	} catch {
		console.log('[*] Elevation required. Prompting for UAC approval...');
		const scriptPath = path.resolve(process.argv[1]);
		const psCmd = `Start-Process cmd.exe -ArgumentList '/k node "${scriptPath}"' -Verb RunAs`;
		try {
			execSync(`powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "${psCmd}"`, {
				stdio: 'inherit',
			});
		} catch (err) {
			console.error('[-] Elevation failed:', err.message);
		}
		process.exit(0);
	}
}

async function prepareEnvironment() {
	if (!fs.existsSync(TOOLS_DIR)) {
		fs.mkdirSync(TOOLS_DIR, { recursive: true });
	}

	for (const tool of SYSINTERNALS_TOOLS) {
		const baseName = tool.replace('64.exe', '').replace('.exe', '');
		try {
			execSync(`reg add "HKCU\\Software\\Sysinternals\\${baseName}" /v EulaAccepted /t REG_DWORD /d 1 /f`, { stdio: 'ignore' });
		} catch { }
	}

	console.log('[*] Verifying/Downloading Sysinternals binaries...');
	for (const tool of SYSINTERNALS_TOOLS) {
		const targetPath = path.join(TOOLS_DIR, tool);
		if (!fs.existsSync(targetPath)) {
			console.log(`[*] Downloading ${tool}...`);
			const res = await fetch(`https://live.sysinternals.com/${tool}`);
			if (!res.ok) throw new Error(`Failed to download ${tool}: ${res.statusText}`);
			fs.writeFileSync(targetPath, Buffer.from(await res.arrayBuffer()));
		}
	}
	console.log(`[+] Tools ready in: ${TOOLS_DIR}\n`);
}

function truncate(str) {
	if (!str) return '';
	if (str.length <= MAX_OUTPUT_CHARS) return str;
	return str.slice(0, MAX_OUTPUT_CHARS) + `\n\n[TRUNCATED: Output exceeded ${MAX_OUTPUT_CHARS} characters. Refine filters/flags.]`;
}

function runPowerShell(command) {
	try {
		const res = spawnSync('powershell.exe', [
			'-NoProfile',
			'-NonInteractive',
			'-ExecutionPolicy', 'Bypass',
			'-Command',
			`[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ${command}`
		], {
			timeout: 90000,
			encoding: 'utf-8',
			windowsHide: true,
			maxBuffer: 20 * 1024 * 1024,
			env: {
				...process.env,
				PATH: `${TOOLS_DIR};${process.env.PATH}`
			}
		});

		if (res.error) return `Execution failed: ${res.error.message}`;
		const output = `${res.stdout || ''}\n${res.stderr || ''}`.trim();
		return truncate(output || '[Command executed with no output]');
	} catch (err) {
		return `Error executing PowerShell: ${err.message}`;
	}
}

const toolDefinitions = [
	{
		type: "function",
		function: {
			name: "run_powershell",
			description: "Executes an elevated PowerShell script or command. Sysinternals binaries are included directly in PATH.",
			parameters: {
				type: "object",
				properties: {
					command: {
						type: "string",
						description: "The PowerShell script block to execute."
					}
				},
				required: ["command"]
			}
		}
	},
	{
		type: "function",
		function: {
			name: "finish_threat_hunt",
			description: "Call this function when the initial investigation is concluded to deliver the findings report.",
			parameters: {
				type: "object",
				properties: {
					threat_level: {
						type: "string",
						enum: ["CLEAN", "SUSPICIOUS_LOW", "SUSPICIOUS_MEDIUM", "COMPROMISED_HIGH", "CRITICAL_SEVERITY"],
						description: "Overall verdict on the host's security posture."
					},
					executive_summary: {
						type: "string",
						description: "A concise overview of the investigation and key anomalies."
					},
					markdown_report: {
						type: "string",
						description: "A comprehensive, structured incident response report in Markdown."
					}
				},
				required: ["threat_level", "executive_summary", "markdown_report"]
			}
		}
	},
	{
		type: "function",
		function: {
			name: "finish_remediation",
			description: "Call this function when threat remediation (process termination, persistence removal, file quarantine) is complete.",
			parameters: {
				type: "object",
				properties: {
					remediation_summary: {
						type: "string",
						description: "A detailed breakdown of all remediation steps taken and their outcomes."
					},
					threats_remaining: {
						type: "boolean",
						description: "Set to true if any threat could not be eradicated and requires manual intervention."
					}
				},
				required: ["remediation_summary", "threats_remaining"]
			}
		}
	}
];

const HUNT_SYSTEM_PROMPT = `You are an autonomous Threat Hunter running directly on a live Windows system with Administrator privileges.

Tools & Binaries Available:
- Standard PowerShell commands, WMI/CIM, Event Logs, Registry, etc.
- Pre-downloaded Sysinternals tools available directly in PATH (located at "${TOOLS_DIR}"):
  * autorunsc64.exe (Persistence checks)
  * sigcheck64.exe (Signature and authenticity checks)
  * tcpvcon64.exe (Active sockets / network connections)
  * pslist64.exe (Process hierarchy and thread views)
  * listdlls64.exe (Loaded modules / DLLs)
  * handle64.exe (Open handles, registry, mutexes)
  * strings64.exe (Extract ASCII/Unicode strings)

Always pipe or filter output with PowerShell to avoid large token-consuming outputs. EULAs have been pre-accepted.

Methodology:
1. Survey active network listeners/sockets and match to process trees.
2. Survey autostart entries (autorunsc64).
3. Verify unsigned binaries, strange paths, and suspicious service/task configurations.
4. Conclude using 'finish_threat_hunt'. Do not take destructive action in this phase.`;

const REMEDIATION_SYSTEM_PROMPT = `You are now an Incident Response Remediation Specialist running with Administrator privileges.
The user has authorized the removal of all confirmed threats identified during the hunt.

Your goal:
1. Safely neutralize identified threats:
   - Terminate active malicious processes (e.g., Stop-Process).
   - Remove malicious persistence hooks (e.g., Unregister-ScheduledTask, Remove-ItemProperty for Run keys, sc.exe delete for services).
   - Quarantine or remove malicious artifacts/binaries.
2. Verify after each action that the process or persistence entry has ceased to exist.
3. Conclude by calling 'finish_remediation' with a full report of actions taken.`;

async function promptUser(question) {
	const rl = readline.createInterface({ input, output });
	const answer = await rl.question(question);
	rl.close();
	return answer.trim().toLowerCase();
}

async function runThreatHunter() {
	ensureElevation();
	const config = loadConfig();
	await prepareEnvironment();

	const openai = new OpenAI({
		apiKey: config.apiKey,
		baseURL: config.baseURL,
	});

	const messages = [
		{ role: 'system', content: HUNT_SYSTEM_PROMPT },
		{ role: 'user', content: 'Begin the threat hunt. Inspect network connections, processes, and persistence hooks.' }
	];

	console.log(`[+] LLM Agent initialized.\n[*] Starting threat hunt...\n`);

	let state = 'HUNTING'; // 'HUNTING' | 'REMEDIATION' | 'DONE'
	let turns = 0;

	while (state !== 'DONE') {
		turns++;
		console.log(`------------------- [${state} Mode - Turn ${turns}] -------------------`);

		let response;
		try {
			response = await openai.chat.completions.create({
				model: config.model,
				messages: messages,
				tools: toolDefinitions,
				tool_choice: "auto",
				temperature: 0.1,
			});
		} catch (err) {
			console.error(`[-] OpenAI API Error:`, err.message);
			break;
		}

		const message = response.choices[0].message;
		messages.push(message);

		if (message.content) {
			console.log(`\n[Agent Reasoning]:\n${message.content}\n`);
		}

		if (!message.tool_calls || message.tool_calls.length === 0) {
			messages.push({
				role: "user",
				content: state === 'HUNTING'
					? "Continue your analysis or execute 'finish_threat_hunt' if complete."
					: "Continue remediation actions or execute 'finish_remediation' if all threats are handled."
			});
			continue;
		}

		for (const toolCall of message.tool_calls) {
			const fnName = toolCall.function.name;
			const args = JSON.parse(toolCall.function.arguments || '{}');

			console.log(`\x1b[36m[*] TOOL CALL: ${fnName}\x1b[0m`);
			console.log(`    Arguments: ${JSON.stringify(args)}`);

			let result = '';

			if (fnName === 'run_powershell') {
				result = runPowerShell(args.command);
			} else if (fnName === 'finish_threat_hunt') {
				console.log(`\n\x1b[32m[+] THREAT HUNT CONCLUDED!\x1b[0m`);
				console.log(`Threat Level: ${args.threat_level}`);
				console.log(`Summary:\n${args.executive_summary}\n`);

				const reportPath = path.resolve(`ThreatHunt_Report_${Date.now()}.md`);
				fs.writeFileSync(reportPath, args.markdown_report, 'utf-8');
				console.log(`\x1b[32m[+] Full Report saved to: ${reportPath}\x1b[0m\n`);

				if (args.threat_level === 'CLEAN') {
					console.log('[+] System is clean. No remediation necessary.');
					state = 'DONE';
					result = "Report generated. Host is clean.";
				} else {
					console.log(`\x1b[33m[!] Threats or anomalies detected (Level: ${args.threat_level}).\x1b[0m`);
					const answer = await promptUser('[?] Do you want the assistant to attempt automated removal/remediation of the identified threats? (yes/no): ');

					if (answer === 'yes' || answer === 'y') {
						console.log('\n[*] Switching agent to REMEDIATION mode...\n');
						state = 'REMEDIATION';
						messages.push({
							role: "tool",
							tool_call_id: toolCall.id,
							content: "Report delivered. User authorized remediation. Switch to remediation mode immediately."
						});
						messages.push({
							role: "system",
							content: REMEDIATION_SYSTEM_PROMPT
						});
						messages.push({
							role: "user",
							content: "The user has approved threat removal. Begin remediating the findings identified in the report. Terminate processes, remove persistence entries, and clean artifacts. Call 'finish_remediation' when finished."
						});
						continue;
					} else {
						console.log('[*] Remediation declined by user. Exiting.');
						state = 'DONE';
						result = "User declined remediation. Investigation complete.";
					}
				}
			} else if (fnName === 'finish_remediation') {
				console.log(`\n\x1b[32m[+] REMEDIATION COMPLETED!\x1b[0m`);
				console.log(`Threats Remaining: ${args.threats_remaining ? 'YES (Manual action needed)' : 'NO (Fully eradicated)'}`);
				console.log(`Summary:\n${args.remediation_summary}\n`);

				const remediationPath = path.resolve(`Remediation_Report_${Date.now()}.md`);
				fs.writeFileSync(remediationPath, args.remediation_summary, 'utf-8');
				console.log(`\x1b[32m[+] Remediation Log saved to: ${remediationPath}\x1b[0m\n`);

				state = 'DONE';
				result = "Remediation concluded successfully.";
			} else {
				result = `Unknown function: ${fnName}`;
			}

			messages.push({
				role: "tool",
				tool_call_id: toolCall.id,
				content: result
			});
		}
	}
}

runThreatHunter().catch(err => {
	console.error('Fatal execution failure:', err);
});