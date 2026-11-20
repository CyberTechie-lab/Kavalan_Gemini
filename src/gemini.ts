import { GoogleGenAI, ThinkingLevel } from '@google/genai';
import { CorrelatedSource } from './types.js';

const DEFAULT_MODEL = 'gemini-4-hydrogen';

const MODEL_ALIASES: Record<string, string> = {
  'gemini-1.5-flash': 'gemini-4-hydrogen',
  'gemini-1.5-pro': 'gemini-4-hydrogen',
  'gemini-2.0-flash': 'gemini-4-hydrogen',
  'gemini-4-hydrogen': 'gemini-4-hydrogen',
  'gemini-3.1-flash-lite': 'gemini-3.1-flash-lite',
};

function normalizeModel(model?: string): string {
  const key = String(model || '').trim();
  if (!key) return DEFAULT_MODEL;
  return MODEL_ALIASES[key] || DEFAULT_MODEL;
}

function tokenizeSecurityPrompt(prompt: string): {
  tokens: string[];
  attention_weights: Array<{ token: string; weight: number }>;
} {
  const rawTokens = prompt
    .split(/(\s+|[,;()[\]{}])/)
    .map((t) => t.trim())
    .filter(Boolean)
    .slice(0, 48);

  const tokens = ['<BOS>', ...rawTokens, '<EOS>'];
  const attention_weights = rawTokens.map((token) => {
    let weight = 0.08;
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(token)) weight = 0.94;
    else if (/^T\d{4}(?:\.\d{3})?$/i.test(token)) weight = 0.89;
    else if (/^(recon_files|command_injection|sql_injection|ssrf|path_traversal|ssh_credential_guessing|firewall-drop|msfadmin|root|admin)$/i.test(token)) {
      weight = 0.82;
    } else if (token.length >= 6) {
      weight = 0.35;
    }
    return { token, weight: Number(weight.toFixed(4)) };
  });

  return { tokens, attention_weights };
}

export class GeminiAIService {
  private runtimeApiKey: string | null = null;
  private activeModel: string = DEFAULT_MODEL;

  private getEffectiveKey(): string {
    return (this.runtimeApiKey || process.env.GEMINI_API_KEY || '').trim();
  }

  private getClient(): GoogleGenAI | null {
    const apiKey = this.getEffectiveKey();
    if (!apiKey) return null;
    return new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }

  isConfigured(): boolean {
    return Boolean(this.getEffectiveKey());
  }

  getModelInfo(): Record<string, any> {
    return {
      model_name: `Google ${this.activeModel}`,
      model_id: this.activeModel,
      provider: 'Google DeepMind',
      context_window: '1,000,000 Tokens',
      memory_footprint_mb: 0.0,
      configured: this.isConfigured(),
    };
  }

  getConfigStatus(): Record<string, any> {
    const key = this.getEffectiveKey();
    const preview = key.length >= 8 ? `${key.slice(0, 4)}...${key.slice(-4)}` : key ? 'Configured' : null;
    return {
      configured: Boolean(key),
      model: this.activeModel,
      key_preview: preview,
      source: this.runtimeApiKey ? 'runtime' : process.env.GEMINI_API_KEY ? 'env' : 'none',
    };
  }

  setConfig(apiKey?: string, model?: string): Record<string, any> {
    if (typeof apiKey === 'string' && apiKey.trim()) {
      this.runtimeApiKey = apiKey.trim();
    }
    if (typeof model === 'string' && model.trim()) {
      this.activeModel = normalizeModel(model);
    }
    return this.getConfigStatus();
  }

  async generate(prompt: string): Promise<Record<string, any>> {
    const start = Date.now();
    const { tokens, attention_weights } = tokenizeSecurityPrompt(prompt);
    const ai = this.getClient();
    if (!ai) {
      return {
        error: 'GEMINI_API_KEY is not configured in environment or server config.',
        generated_text:
          'GEMINI_API_KEY is not configured. Set GEMINI_API_KEY in Secrets/environment or configure a key above to run live Gemini inference.',
        inference_time_ms: Date.now() - start,
        generated_tokens_count: 0,
        prompt_tokens: tokens,
        tokens,
        attention_weights,
        model: this.activeModel,
      };
    }

    try {
      const response = await ai.models.generateContent({
        model: this.activeModel,
        contents: prompt,
        config: {
          systemInstruction:
            'You are Kavalan SIEM AI Security Analyst. Provide concise, accurate, technical SOC triage, MITRE ATT&CK mapping, autonomous agent attribution, and defensive remediation commands.',
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
        },
      });
      const text = (response.text || '').trim() || 'No response text returned from Gemini.';
      const tokenCount = text.split(/\s+/).filter(Boolean).length;
      return {
        generated_text: text,
        inference_time_ms: Date.now() - start,
        generated_tokens_count: tokenCount,
        prompt_tokens: tokens,
        tokens,
        attention_weights,
        model: this.activeModel,
      };
    } catch (err: any) {
      const msg = err?.message || 'Gemini API call failed.';
      return {
        error: msg,
        generated_text: `Gemini API Error: ${msg}`,
        inference_time_ms: Date.now() - start,
        generated_tokens_count: 0,
        prompt_tokens: tokens,
        tokens,
        attention_weights,
        model: this.activeModel,
      };
    }
  }

  async explainAlert(params: {
    alert_summary: string;
    ip?: string;
    tactics?: Record<string, number> | string[];
    level?: string | number;
  }): Promise<Record<string, any>> {
    const tacticsText = Array.isArray(params.tactics)
      ? params.tactics.join(', ')
      : params.tactics
      ? Object.keys(params.tactics).join(', ')
      : 'general probing';
    const prompt = `Analyze this SIEM security alert and provide root-cause assessment and containment commands:
Alert: ${params.alert_summary || 'Security anomaly'}
Source IP: ${params.ip || 'unknown'}
Severity Level: ${params.level || 'HIGH'}
Observed Tactics: ${tacticsText}`;
    return this.generate(prompt);
  }
}

export class AIAttackAnalyst {
  constructor(private gemini: GeminiAIService) {}

  async analyzeActor(
    ip: string | null,
    sources: CorrelatedSource[],
    _events: any[],
    alerts: any[]
  ): Promise<Record<string, any>> {
    const target =
      (ip ? sources.find((s) => s.ip === ip) : null) ||
      [...sources].sort((a, b) => Math.max(b.web_score, b.ssh_score) - Math.max(a.web_score, a.ssh_score))[0] ||
      null;

    if (!target) {
      return {
        ip: ip || 'No Active Actor',
        classification: 'BASELINE / NO ACTIVE THREAT',
        agent_confidence: 0,
        executive_summary:
          'No active threat actor telemetry was found in the current correlation window. Trigger a Red Team simulation or ingest telemetry to analyze an actor.',
        ai_indicators: ['No anomalous burst or cross-source pivots observed'],
        attack_phases: [],
        playbook: [],
      };
    }

    const score = Math.min(99, Math.max(target.web_score || 0, target.ssh_score || 0, target.cross_source ? 88 : 45));
    const tacticKeys = Object.keys(target.tactics || {});
    const mitreList = Object.values(target.mitre_tactics || {});
    const isAutonomous =
      target.cross_source ||
      (target.switches ?? 0) >= 3 ||
      tacticKeys.length >= 3 ||
      score >= 75;

    const classification = isAutonomous
      ? 'AUTONOMOUS AI OFFENSIVE AGENT'
      : target.level === 'CRITICAL' || target.level === 'HIGH'
      ? 'AUTOMATED EXPLOIT / SCANNER'
      : 'SUSPICIOUS CLIENT ACTIVITY';

    const aiIndicators: string[] = [];
    if (target.cross_source) {
      aiIndicators.push(`Cross-source telemetry pivot across [${target.channels.join(', ')}]`);
    }
    if ((target.switches ?? 0) >= 2) {
      aiIndicators.push(`Rapid tactic-switching cadence (${target.switches} distinct transitions)`);
    }
    if ((target.distinct_paths ?? 0) >= 5) {
      aiIndicators.push(`High-entropy path discovery (${target.distinct_paths} distinct targets)`);
    }
    if ((target.sensitive_hits ?? 0) > 0) {
      aiIndicators.push(`Targeted probing of sensitive endpoints (${target.sensitive_hits} hits)`);
    }
    if (target.multi_host) {
      aiIndicators.push(`Multi-host lateral sweep across [${target.hosts.join(', ')}]`);
    }
    if (aiIndicators.length === 0) {
      aiIndicators.push(...(target.reasons || ['Observed automated probing heuristics']).slice(0, 4));
    }

    const attackPhases = mitreList.length
      ? mitreList.map((m, idx) => ({
          phase: `Phase ${idx + 1}: ${m.name}`,
          tactic: `${m.id} (${m.tactic})`,
          description: `Observed adversary activity matching ${m.tactic} techniques targeting ${target.hosts.join(', ') || 'monitored fleet'}.`,
          evidence: `Actor ${target.ip} · Channels: ${target.channels.join(', ')}`,
        }))
      : tacticKeys.map((t, idx) => ({
          phase: `Phase ${idx + 1}: ${t.replace(/_/g, ' ')}`,
          tactic: t,
          description: `Telemetry matched heuristic tactic '${t}' across ${target.tactics[t]} event(s).`,
          evidence: `Actor ${target.ip} · Hosts: ${target.hosts.join(', ') || 'fleet'}`,
        }));

    const playbook = [
      {
        step: 1,
        action: 'Perimeter Firewall Drop (Fleetwide)',
        description: `Block source IP ${target.ip} across all enrolled endpoints via Active Response.`,
        command: `iptables -I INPUT 1 -s ${target.ip} -j DROP`,
      },
      {
        step: 2,
        action: 'Audit Targeted Host Connections & Sessions',
        description: `Inspect active sockets and recent authentication sessions on ${target.hosts[0] || 'web-01'}.`,
        command: `ss -tunap | grep ${target.ip} && last -a | head -n 20`,
      },
      {
        step: 3,
        action: 'Escalate & Preserve Forensic Evidence',
        description: 'Open an incident case and verify cold archive hash-chain integrity.',
        command: `kavalan-ctl case create --ip ${target.ip} --severity ${target.level}`,
      },
    ];

    let executiveSummary = `Actor ${target.ip} (${target.level}) executed ${
      tacticKeys.length || 1
    } distinct tactic(s) across ${target.hosts.join(', ') || 'monitored hosts'} via ${
      target.channels.join(' + ') || 'telemetry'
    } (Web score: ${target.web_score}, SSH score: ${target.ssh_score}).${
      target.breached ? ' Confirmed authentication breach indicator detected.' : ''
    }`;

    if (this.gemini.isConfigured()) {
      const prompt = `Write a crisp 2-sentence SOC executive threat summary for IP ${target.ip} (${classification}, score ${score}/100, channels ${target.channels.join(', ')}, hosts ${target.hosts.join(', ')}, tactics ${tacticKeys.join(', ')}, alert count ${alerts.length}).`;
      const gem = await Promise.race([
        this.gemini.generate(prompt),
        new Promise<null>((resolve) => setTimeout(() => resolve(null), 3500)),
      ]);
      if (gem && !gem.error && gem.generated_text) {
        executiveSummary = gem.generated_text;
      }
    }

    return {
      ip: target.ip,
      classification,
      agent_confidence: score,
      executive_summary: executiveSummary,
      ai_indicators: aiIndicators,
      attack_phases: attackPhases,
      playbook,
    };
  }

  async chat(
    message: string,
    ctx: { sources: CorrelatedSource[]; alerts: any[]; totalEvents: number; activeAgents: number }
  ): Promise<Record<string, any>> {
    const topSource = ctx.sources[0];
    const suggestions = [
      topSource ? `Analyze actor ${topSource.ip} tactics` : 'Summarize current fleet posture',
      'Show containment commands for highest-risk IP',
      'Explain MITRE ATT&CK techniques observed',
    ];

    if (this.gemini.isConfigured()) {
      const contextSummary = `Active Agents: ${ctx.activeAgents}, Indexed Events: ${ctx.totalEvents}, Open Alerts: ${ctx.alerts.length}, Top Actors: ${ctx.sources
        .slice(0, 3)
        .map((s) => `${s.ip}(${s.level}, web=${s.web_score}, ssh=${s.ssh_score})`)
        .join('; ') || 'none'}`;
      const res = await this.gemini.generate(`SOC Context: ${contextSummary}\n\nAnalyst Question: ${message}`);
      if (!res.error) {
        return {
          reply: res.generated_text,
          suggestions,
          model: res.model,
        };
      }
      return {
        reply: `Gemini API Error: ${res.error}`,
        suggestions,
      };
    }

    return {
      reply:
        `### Gemini API Key Required for Freeform Copilot Chat\n` +
        `Current live fleet context: **${ctx.activeAgents}** active agents, **${ctx.totalEvents}** indexed events, **${ctx.alerts.length}** correlated alert(s)` +
        (topSource
          ? `, top actor **${topSource.ip}** (${topSource.level}, tactics: \`${Object.keys(topSource.tactics || {}).join(', ') || 'probe'}\`).`
          : '.') +
        `\n\nConfigure \`GEMINI_API_KEY\` in environment secrets to enable live Gemini conversational responses.`,
      suggestions,
    };
  }
}
