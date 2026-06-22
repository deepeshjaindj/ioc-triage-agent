
import { Mastra } from '@mastra/core/mastra';
import { PinoLogger } from '@mastra/loggers';
import { LibSQLStore } from '@mastra/libsql';
import { MastraCompositeStore } from '@mastra/core/storage';
import { Observability, MastraStorageExporter, MastraPlatformExporter, SensitiveDataFilter } from '@mastra/observability';
import { weatherWorkflow } from './workflows/weather-workflow';
import { iocTriageWorkflow } from './workflows/ioc-triage-workflow';
import { weatherAgent } from './agents/weather-agent';
import { iocTriageAgent } from './agents/ioc-triage-agent';
import { toolCallAppropriatenessScorer, completenessScorer, translationScorer } from './scorers/weather-scorer';
import {
  toolCallAppropriatenessScorer as iocToolCallScorer,
  verdictGroundingScorer,
} from './scorers/ioc-triage-scorer';

// Netlify Functions run on an ephemeral filesystem and bundle without native
// modules, so a file-based LibSQL DB and the DuckDB native store don't work
// there. Pick storage per environment:
//   - Serverless: LibSQL. Set DATABASE_URL + DATABASE_AUTH_TOKEN (e.g. a free
//     Turso DB) for memory that persists across requests; otherwise it falls
//     back to in-memory (stateless per cold start).
//   - Local dev: keep the original file-based LibSQL + DuckDB observability store.
//
// IMPORTANT: detect serverless via BOTH the build flag (NETLIFY, set during
// `netlify build`) AND the Lambda runtime flags (LAMBDA_TASK_ROOT /
// AWS_LAMBDA_FUNCTION_NAME, set when the function actually executes). NETLIFY is
// NOT present at function runtime, so relying on it alone makes the runtime take
// the DuckDB branch and crash with "Cannot find package '@mastra/duckdb'".
const isServerless =
  !!process.env.NETLIFY ||
  !!process.env.LAMBDA_TASK_ROOT ||
  !!process.env.AWS_LAMBDA_FUNCTION_NAME;

async function buildStorage() {
  if (isServerless) {
    return new LibSQLStore({
      id: 'mastra-storage',
      url: process.env.DATABASE_URL ?? ':memory:',
      authToken: process.env.DATABASE_AUTH_TOKEN,
    });
  }
  // Non-literal specifier keeps DuckDB (native bindings) out of the serverless bundle.
  const duckdbModule = '@mastra/duckdb';
  const { DuckDBStore } = await import(/* @vite-ignore */ duckdbModule);
  return new MastraCompositeStore({
    id: 'composite-storage',
    default: new LibSQLStore({ id: 'mastra-storage', url: 'file:./mastra.db' }),
    domains: {
      observability: await new DuckDBStore().getStore('observability'),
    },
  });
}

const storage = await buildStorage();

// The Netlify deployer is build-time tooling only (it pulls in TypeScript,
// rollup, babel, esbuild). It must be present when `mastra build` evaluates this
// module, but it must NOT end up installed in the deployed function — that pushed
// the bundle past Netlify's 250 MB limit. So load it via a non-literal dynamic
// import (invisible to the bundler) and skip it entirely inside the Lambda
// runtime, where `LAMBDA_TASK_ROOT` is set.
const isLambdaRuntime = !!process.env.LAMBDA_TASK_ROOT || !!process.env.AWS_LAMBDA_FUNCTION_NAME;

async function buildDeployer() {
  if (isLambdaRuntime) return undefined;
  try {
    const deployerModule = '@mastra/deployer-netlify';
    const { NetlifyDeployer } = await import(/* @vite-ignore */ deployerModule);
    return new NetlifyDeployer();
  } catch {
    // Package not available at runtime — fine, it's only needed during build.
    return undefined;
  }
}

// NOTE: this const must be named `deployer` and passed as the shorthand
// `deployer` property below. Mastra's build statically extracts the deployer by
// finding a `deployer:` property whose value is an identifier named `deployer`,
// then inlines this initializer into a separate build-only bundle. Renaming it
// or hiding it behind a spread breaks deployer detection.
const deployer = await buildDeployer();

export const mastra = new Mastra({
  workflows: { weatherWorkflow, iocTriageWorkflow },
  agents: { weatherAgent, iocTriageAgent },
  scorers: {
    toolCallAppropriatenessScorer,
    completenessScorer,
    translationScorer,
    iocToolCallScorer,
    verdictGroundingScorer,
  },
  storage,
  logger: new PinoLogger({
    name: 'Mastra',
    level: 'info',
  }),
  observability: new Observability({
    configs: {
      default: {
        serviceName: 'mastra',
        exporters: [
          new MastraStorageExporter(), // Persists observability events to Mastra Storage
          new MastraPlatformExporter(), // Sends observability events to Mastra Platform (if MASTRA_PLATFORM_ACCESS_TOKEN is set)
        ],
        spanOutputProcessors: [
          new SensitiveDataFilter(), // Redacts sensitive data like passwords, tokens, keys
        ],
      },
    },
  }),
  deployer,
  // `pnpapi` is the Yarn PnP runtime, referenced transitively during the build
  // but absent in a normal npm install; a local no-op stub + this external keep
  // the build's import check happy.
  bundler: {
    externals: ['pnpapi'],
  },
});
