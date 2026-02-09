# FalconEYE

```
███████╗ █████╗ ██╗      ██████╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗███████╗
██╔════╝██╔══██╗██║     ██╔════╝██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔════╝
█████╗  ███████║██║     ██║     ██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ █████╗
██╔══╝  ██╔══██║██║     ██║     ██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔══╝
██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████╗   ██║   ███████╗
╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝
```

**Next-Generation Security Code Analysis Powered by Local LLMs**

*by hardw00t & h4ckologic*

FalconEYE represents a paradigm shift in static code analysis. Instead of relying on predefined vulnerability patterns, it leverages large language models to reason about your code the same way a security expert would — understanding context, intent, and subtle security implications that traditional tools miss.

---

## Table of Contents

- [Why FalconEYE?](#why-falconeye)
- [How It Works](#how-it-works)
- [Getting Started](#getting-started)
- [MLX Backend (Apple Silicon)](#mlx-backend-apple-silicon)
- [Supported Languages](#supported-languages)
- [CLI Reference](#cli-reference)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Development](#development)
- [FAQ](#faq)
- [License](#license)

---

## Why FalconEYE?

Traditional security scanners are limited by their pattern databases. They can only find what they've been programmed to look for. FalconEYE is different:

- **No Pattern Matching** — Uses pure AI reasoning to understand your code semantically
- **Context-Aware Analysis** — Retrieval-Augmented Generation (RAG) provides relevant code context for deeper insights
- **Novel Vulnerability Detection** — Identifies security issues that don't match known patterns
- **LLM-Powered Enrichment** — Every finding gets AI-generated descriptions, mitigations, code snippets, and line numbers
- **Reduced False Positives** — Optional AI validation pass filters noise from false alarms
- **Rich Reporting** — Console, JSON, HTML, and SARIF output with interactive dashboards
- **Smart Re-indexing** — Incremental analysis means re-scans only process changed files
- **Privacy-First** — Runs entirely locally with Ollama or MLX — your code never leaves your machine
- **Apple Silicon Accelerated** — Native MLX backend delivers 20-40% faster inference on M-series chips

---

## How It Works

FalconEYE follows a multi-stage analysis pipeline:

```
┌─────────────────────────────────────────────────────────────────┐
│                     1. CODE INGESTION                          │
│  Scans repository -> Detects languages -> Parses AST structure │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                    2. INTELLIGENT INDEXING                      │
│  Chunks code semantically -> Generates embeddings -> Stores in │
│  vector database for fast semantic search                      │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                   3. CONTEXT ASSEMBLY (RAG)                     │
│  For each code segment -> Retrieves similar code -> Gathers    │
│  relevant context from your entire codebase                    │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                    4. AI SECURITY ANALYSIS                      │
│  LLM analyzes code with context -> Reasons about vulns ->      │
│  Understands data flow -> Identifies security implications     │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                   5. LLM-POWERED ENRICHMENT                    │
│  Incomplete findings sent back to the LLM for detailed         │
│  reasoning, specific mitigations, code snippets & line numbers │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                     6. VALIDATION & REPORTING                  │
│  Optional AI validation pass -> Formats findings -> Outputs in │
│  Console/JSON/HTML/SARIF format with actionable remediation    │
└─────────────────────────────────────────────────────────────────┘
```

**Semantic Understanding**: FalconEYE reads your code like a security engineer, understanding business logic, data flows, and architectural patterns to identify real vulnerabilities.

**RAG-Enhanced Analysis**: By retrieving similar code patterns from your entire codebase, the AI gets crucial context about how functions are used, what data they handle, and potential security implications across your application.

**LLM-Powered Enrichment**: When the initial analysis produces incomplete findings (missing line numbers, generic descriptions, or vague mitigations), FalconEYE sends them back to the LLM with the full source code for enrichment. Every displayed finding includes specific line numbers, the vulnerable code snippet, a detailed description of the exploit, and actionable remediation referencing actual identifiers from your code.

---

## Getting Started

### Prerequisites

- **Python 3.12+**
- **Ollama** running locally ([Install Ollama](https://ollama.ai))

### Installation

```bash
# Pull required AI models
ollama pull qwen3-coder:30b
ollama pull embeddinggemma:300m

# Install FalconEYE
pip install -e .
```

### Apple Silicon Installation (MLX)

For native Apple Silicon acceleration:

```bash
# Pull embedding model (still required -- MLX uses Ollama for embeddings)
ollama pull embeddinggemma:300m

# Install FalconEYE with MLX support
pip install -e ".[mlx]"
```

> **Note**: MLX requires an Apple Silicon Mac (M1/M2/M3/M4). The MLX backend uses a hybrid approach — MLX handles LLM inference while Ollama handles embeddings. Ollama must still be running for the indexing step. The MLX analysis model is downloaded automatically from HuggingFace on first use.

### Your First Scan

```bash
# Full scan (index + review in one step)
falconeye scan /path/to/your/project

# Or run the steps separately:
falconeye index /path/to/your/project     # Index codebase (one-time)
falconeye review /path/to/your/project    # Analyze for vulnerabilities

# Scan with MLX backend on Apple Silicon
falconeye scan /path/to/your/project --backend mlx

# Generate an HTML report
falconeye scan /path/to/your/project --format html --output report.html

# Verbose mode -- see LLM streaming and full logs
falconeye scan /path/to/your/project -v
```

---

## MLX Backend (Apple Silicon)

FalconEYE supports native Apple Silicon inference via [MLX](https://github.com/ml-explore/mlx), Apple's machine learning framework optimized for the unified memory architecture and Neural Engine of M-series chips.

### Performance Benefits

MLX delivers significant performance improvements over Ollama (which uses llama.cpp internally) on Apple Silicon hardware:

| Metric | Improvement | Details |
|--------|-------------|---------|
| **Token Generation** | **20-40% faster** | MLX runs inference directly on the Apple GPU/Neural Engine. On MoE models like Qwen3-30B-A3B, benchmarks show 17-43% higher tok/s vs llama.cpp. Smaller models see up to 87% gains. |
| **Memory Usage** | **~30% lower RAM** | Zero-copy unified memory eliminates data duplication between CPU and GPU. Lazy evaluation fuses operations and reduces allocation overhead. |
| **First-Token Latency** | **~50% lower** | In-process inference removes the HTTP round-trip overhead of Ollama's REST API on localhost:11434. |
| **Prompt Processing** | **~25% faster prefill** | Native Metal compute path vs llama.cpp's Metal abstraction layer. |
| **Model Availability** | **Broader selection** | Access thousands of quantized models from HuggingFace's `mlx-community`, compared to Ollama's curated library. |

> Figures based on published benchmarks of MLX vs llama.cpp on M-series chips (Barrios et al., arXiv:2601.19139; arXiv:2511.05502; Google Cloud Community Gemma 3 benchmarks). Actual results vary by model size, quantization level, and hardware generation.

**When to use MLX:**
- You have an Apple Silicon Mac (M1/M2/M3/M4)
- You want faster scan times and lower memory consumption
- You want access to the latest quantized models from HuggingFace

**When to stick with Ollama:**
- Cross-platform deployment (Linux, Intel Mac, Windows via WSL)
- You prefer Ollama's curated model library and CLI tooling
- Running on non-Apple hardware

### Hybrid Architecture

The MLX backend uses a hybrid approach because MLX does not natively support embedding models:

```
                 ┌──────────────────────────┐
                 │      FalconEYE CLI       │
                 └────────────┬─────────────┘
                              │
              ┌───────────────┴───────────────┐
              │                               │
    ┌─────────▼──────────┐        ┌──────────▼──────────┐
    │   MLX (Analysis)   │        │  Ollama (Embeddings) │
    │                    │        │                      │
    │  Qwen3-Coder-30B  │        │  embeddinggemma:300m │
    │  4-bit quantized   │        │                      │
    │  Apple Silicon GPU │        │  localhost:11434     │
    └────────────────────┘        └──────────────────────┘
```

- **Inference**: MLX loads a quantized model directly into unified memory and runs on the Apple GPU/Neural Engine. Zero-copy memory access eliminates transfer overhead.
- **Embeddings**: Ollama handles embedding generation during the indexing step. Ollama must be running when you use `falconeye index` or `falconeye scan`.

### MLX Model Configuration

The default model is `mlx-community/Qwen3-Coder-30B-A3B-Instruct-4bit` — a Mixture-of-Experts model (30B total / 3B active parameters, 4-bit quantized). You can change the model in your config:

```yaml
llm:
  provider: mlx
  mlx:
    analysis: mlx-community/Qwen3-Coder-30B-A3B-Instruct-4bit
```

Any MLX-compatible model from HuggingFace's `mlx-community` namespace can be used. The model is downloaded and cached automatically on first use.

### Checking MLX Availability

```bash
falconeye info
```

The `info` command shows whether your system supports MLX, including Apple Silicon detection and package availability.

---

## Supported Languages

FalconEYE analyzes code in 10 languages with language-specific security knowledge:

| Language | Extensions | Key Vulnerability Categories |
|----------|-----------|------------------------------|
| **Python** | `.py`, `.pyw` | Command/code injection, pickle deserialization, SSRF, Django/Flask/FastAPI issues |
| **JavaScript / TypeScript** | `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs` | XSS, prototype pollution, eval injection, Node.js/React/Express issues |
| **Go** | `.go` | Command injection, SQL injection, race conditions, goroutine leaks |
| **Rust** | `.rs` | Unsafe blocks, FFI issues, integer overflow, Actix/Axum/Rocket issues |
| **C / C++** | `.c`, `.cpp`, `.cc`, `.cxx`, `.h`, `.hpp`, `.hxx` | Buffer overflow, format strings, use-after-free, memory corruption |
| **Java** | `.java` | SQL injection, deserialization, XXE, Spring/Hibernate issues |
| **PHP** | `.php`, `.phtml`, `.php3`-`.php5`, `.phps` | SQL injection, type juggling, RCE, Laravel/WordPress issues |
| **Ruby** | `.rb`, `.rake`, `.gemspec`, `Gemfile`, `Rakefile` | YAML deserialization, mass assignment, eval/send injection, Rails issues |
| **Dart** | `.dart` | Insecure HTTP, hardcoded secrets, path traversal, Flutter issues |

Each language has a dedicated plugin with tailored security prompts, vulnerability categories, and framework-specific context. New languages can be added by implementing the `LanguagePlugin` interface.

---

## CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `falconeye scan <path>` | Index and review in one step |
| `falconeye index <path>` | Index codebase for analysis |
| `falconeye review <path>` | Analyze code for vulnerabilities |
| `falconeye info` | System and configuration information |
| `falconeye config --init` | Create default configuration file |
| `falconeye projects list` | Show all indexed projects |
| `falconeye projects info <id>` | Display project details |
| `falconeye projects delete <id>` | Delete a project and its data |
| `falconeye projects cleanup <id>` | Remove orphaned project data |

### Common Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--backend` | `-b` | LLM backend: `ollama` (default) or `mlx` |
| `--verbose` | `-v` | Detailed output with LLM streaming and full logs |
| `--language` | `-l` | Programming language (auto-detected if omitted) |
| `--config` | `-c` | Path to configuration file |
| `--format` | `-o` | Output format: `console`, `json`, `html`, `sarif` |
| `--output-file` | | Save results to a specific file |
| `--validate` | | Enable AI validation pass to reduce false positives |
| `--top-k` | | Number of similar code chunks for RAG context (default: 5) |
| `--severity` | | Minimum severity to report: `critical`, `high`, `medium`, `low` |
| `--force-reindex` | | Force re-index all files (ignore cache) |
| `--exclude` | `-e` | Glob patterns to exclude (repeatable) |

### Examples

```bash
# Full scan with MLX backend
falconeye scan ./src --backend mlx

# Review with AI validation and HTML output
falconeye review ./src --validate --format html --output report.html

# Scan with verbose output (see LLM reasoning in real-time)
falconeye scan ./src -v

# Filter findings by severity
falconeye review ./src --severity high

# SARIF output for CI/CD integration
falconeye review ./src --format sarif --output results.sarif

# Force re-index and scan
falconeye scan ./src --force-reindex

# Exclude test directories
falconeye scan ./src --exclude "tests/*" --exclude "vendor/*"
```

### Verbose Mode

**Normal mode** (default): Clean progress bar with file count and percentage. Findings are displayed after LLM enrichment completes with full details.

**Verbose mode** (`-v`): Full indexing logs, LLM thought process streaming, detailed progress information, and complete error stack traces.

---

## Output Formats

### Console
Color-coded terminal output with Rich formatting:
```
╭─ SQL Injection Vulnerability ────────────────────────────────╮
│ Severity: HIGH | CWE-89                                     │
│ File: app/database.py (lines 42-45)                         │
│                                                             │
│ The function executes raw SQL with user input without       │
│ parameterization, allowing SQL injection attacks.           │
│                                                             │
│ Recommendation:                                             │
│ Replace the string concatenation in `execute_query()` at    │
│ line 43 with parameterized queries using `cursor.execute(   │
│ "SELECT * FROM users WHERE id = ?", (user_id,))`.          │
╰─────────────────────────────────────────────────────────────╯
```

### JSON
Machine-readable format for CI/CD integration and programmatic processing.

### HTML
Interactive reports with executive summaries, severity charts, and detailed finding cards. Auto-generated alongside JSON when no output file is specified.

### SARIF
Industry-standard format for GitHub Security, GitLab, and DevSecOps platforms.

**Default behavior**: When no output file is specified, FalconEYE saves both JSON and HTML reports to `./falconeye_reports/` with timestamps.

---

## Configuration

FalconEYE uses a hierarchical configuration system. Files are loaded in order (later overrides earlier):

1. Default config: `<install-dir>/config.yaml`
2. User config: `~/.falconeye/config.yaml`
3. Project config: `./falconeye.yaml`

Create `~/.falconeye/config.yaml` to customize:

```yaml
llm:
  provider: ollama                  # LLM provider: "ollama" or "mlx"
  model:
    analysis: qwen3-coder:30b      # AI model for security analysis
    embedding: embeddinggemma:300m  # Model for code embeddings
  base_url: http://localhost:11434
  timeout: 600                      # Request timeout in seconds
  mlx:
    analysis: mlx-community/Qwen3-Coder-30B-A3B-Instruct-4bit  # MLX model

analysis:
  top_k_context: 5          # Number of similar code chunks for RAG context
  validate_findings: true    # Enable AI validation pass
  batch_size: 10            # Files per batch

output:
  default_format: json      # console, json, html, sarif
  color: true               # Color-coded console output
  output_directory: ./falconeye_reports

logging:
  level: INFO               # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: ./falconeye.log
  console: true
  rotation: daily
  retention_days: 30
```

See the [default config.yaml](config.yaml) for all available options.

---

## Architecture

FalconEYE follows hexagonal (ports and adapters) architecture for clean separation of concerns:

```
┌──────────────────────────────────────────────────────────────┐
│                      ADAPTERS LAYER                          │
│  CLI (Typer)  |  Console/HTML/JSON/SARIF Formatters          │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                    APPLICATION LAYER                          │
│  IndexCodebaseCommand  |  ReviewFileCommand                  │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                      DOMAIN LAYER                            │
│  SecurityAnalyzer  |  ContextAssembler  |  Models  |  Ports  │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                   INFRASTRUCTURE LAYER                        │
│  Ollama Adapter  |  MLX Adapter  |  ChromaDB  |  Plugins     │
│  Config Loader   |  DI Container |  Language Detection       │
└──────────────────────────────────────────────────────────────┘
```

**Key design decisions:**
- Domain layer defines abstract ports (`LLMService`, `VectorStore`); infrastructure provides concrete adapters
- DI container wires everything together with a factory pattern (`backend_override` selects MLX or Ollama)
- Language plugins are self-contained: each provides security prompts, vulnerability categories, framework context, and chunking strategies
- Circuit breaker and retry patterns protect against LLM failures
- Structured JSON logging with correlation IDs

---

## Development

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Install with MLX support (Apple Silicon)
pip install -e ".[mlx]"

# Run test suite
pytest

# Run integration tests (requires Ollama)
pytest tests/integration/ -v
```

---

## FAQ

**Q: Does my code get sent to external services?**
A: No. FalconEYE runs entirely locally using Ollama or MLX. Your code never leaves your machine.

**Q: How accurate is AI-based analysis compared to traditional scanners?**
A: FalconEYE complements traditional tools. It excels at finding context-dependent vulnerabilities and novel patterns that signature-based tools miss. The LLM enrichment pass ensures every finding includes specific details, and the optional AI validation pass reduces false positives.

**Q: Can I use different AI models?**
A: Yes. Configure any Ollama-compatible model in your config file. On Apple Silicon, you can also use any MLX-compatible model from HuggingFace's `mlx-community` namespace by setting `--backend mlx`.

**Q: What is the MLX backend and why should I use it?**
A: MLX is Apple's ML framework for Apple Silicon. It provides 20-40% faster inference, ~30% lower memory usage, and ~50% lower first-token latency compared to Ollama by leveraging unified memory and running inference directly on the GPU/Neural Engine without HTTP overhead. Use `--backend mlx` or set `provider: mlx` in your config.

**Q: How does FalconEYE handle incomplete findings from local models?**
A: Local models (especially smaller quantized ones) sometimes produce findings with missing line numbers, vague descriptions, or generic mitigations. FalconEYE detects incomplete findings and automatically sends them back to the LLM with the full source code for enrichment — producing specific descriptions, actionable mitigations referencing actual identifiers, code snippets, and accurate line numbers.

**Q: How do I integrate this into CI/CD?**
A: Use SARIF output format (`--format sarif`) which integrates with GitHub Security, GitLab, and most DevSecOps platforms.

**Q: How long does analysis take?**
A: Initial indexing depends on codebase size. Subsequent scans with smart re-indexing only process changed files. Using the MLX backend on Apple Silicon reduces analysis time by 20-40% compared to Ollama.

---

## License

FalconEYE is licensed under the GNU Affero General Public License v3.0 or later (AGPLv3+).

See the [LICENSE](LICENSE) file for the complete license text.

Copyright (c) 2025 hardw00t & h4ckologic

---

## Quick Reference

```bash
# Full scan (index + review)
falconeye scan /path/to/project

# Scan with MLX backend (Apple Silicon)
falconeye scan /path/to/project --backend mlx

# Review only (requires prior indexing)
falconeye review /path/to/project

# Generate HTML report
falconeye review /path/to/project --format html --output report.html

# Filter by severity
falconeye review /path/to/project --severity high

# Verbose mode with LLM streaming
falconeye scan /path/to/project -v

# System information (shows MLX availability)
falconeye info

# List indexed projects
falconeye projects list
```

### Default Output Locations
- **Reports**: `./falconeye_reports/`
- **Logs**: `./falconeye.log`
- **Config**: `~/.falconeye/config.yaml`

---

**Built for security engineers who demand more than pattern matching.**

Version 2.0.0 | Python 3.12+ | Ollama + MLX

By [hardw00t](https://github.com/hardw00t) & [h4ckologic](https://github.com/h4ckologic)
