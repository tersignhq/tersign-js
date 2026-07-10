#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { buildServer, envDeps } from './server.js';

const server = buildServer(envDeps());
await server.connect(new StdioServerTransport());
