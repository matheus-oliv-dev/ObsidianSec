#!/usr/bin/env node
import { SecuritySquadOrchestrator } from "../src/agents/core/agent-runner.ts";

const targetUrl = process.argv[2];

const squad = new SecuritySquadOrchestrator(targetUrl);
squad.runFullSquadAudit().catch(console.error);
