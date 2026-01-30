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

FalconEYE represents a paradigm shift in static code analysis. Instead of relying on predefined vulnerability patterns, it leverages large language models to reason about your code the same way a security expert would—understanding context, intent, and subtle security implications that traditional tools miss.

## Why FalconEYE?

Traditional security scanners are limited by their pattern databases. They can only find what they've been programmed to look for. FalconEYE is different:

- **No Pattern Matching**: Uses pure AI reasoning to understand your code semantically
- **Context-Aware Analysis**: Retrieval-Augmented Generation provides relevant code context for deeper insights
- **Novel Vulnerability Detection**: Identifies security issues that don't match known patterns
- **Reduced False Positives**: AI validation reduces noise from pattern-based false alarms
- **Rich HTML Reports**: Auto-generated interactive reports with executive dashboards and statistics
- **Smart & Fast**: Incremental analysis means re-scans only process changed files
- **Privacy-First**: Runs entirely locally with Ollama—your code never leaves your machine

## How It Works

FalconEYE follows a sophisticated analysis pipeline:

```
┌─────────────────────────────────────────────────────────────────┐
│                     1. CODE INGESTION                            │
│  Scans repository → Detects languages → Parses AST structure    │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                    2. INTELLIGENT INDEXING                       │
│  Chunks code semantically → Generates embeddings → Stores in    │
│  vector database for fast semantic search                       │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                   3. CONTEXT ASSEMBLY (RAG)                      │
│  For each code segment → Retrieves similar code → Gathers       │
│  relevant context from your entire codebase                     │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                    4. AI SECURITY ANALYSIS                       │
│  LLM analyzes code with context → Reasons about vulnerabilities │
│  → Understands data flow → Identifies security implications     │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                     5. VALIDATION & REPORTING                    │
│  Optional AI validation pass → Formats findings → Outputs in    │
│  Console/JSON/SARIF format with actionable remediation          │
└─────────────────────────────────────────────────────────────────┘
```

### What Makes This Special?

**Semantic Understanding**: FalconEYE doesn't just scan for known patterns. It reads your code like a security engineer would, understanding business logic, data flows, and architectural patterns to identify real vulnerabilities.

**Smart Re-indexing**: After the initial scan, FalconEYE tracks file changes and only re-analyzes what's changed. This makes subsequent scans dramatically faster while maintaining comprehensive coverage.

**RAG-Enhanced Analysis**: By retrieving similar code patterns from your entire codebase, the AI gets crucial context about how functions are used, what data they handle, and potential security implications across your application.

## Getting Started

### Prerequisites

1. **Python 3.12+** installed
2. **Ollama** running locally ([Install Ollama](https://ollama.ai))

### Installation

```bash
# Pull required AI models
ollama pull qwen3-coder:30b
ollama pull embeddinggemma:300m

# Install FalconEYE
pip install -e .
```

FalconEYE will use the default configuration on first run. You can customize settings by creating `~/.falconeye/config.yaml` (see [Configuration](#configuration) section).

## License

FalconEYE is dual-licensed under AGPLv3 and a commercial license.

### AGPLv3 License

Free for non-commercial use including:
- Non-profit organizations
- Academic research and educational institutions
- Personal projects
- Open source projects compliant with AGPLv3

Under AGPLv3, you must share your source code and any modifications when distributing or providing FalconEYE as a network service.

### Commercial License

A commercial license is required for:
- Integrating FalconEYE into proprietary or closed-source products
- Offering FalconEYE as a commercial service or SaaS platform
- Using FalconEYE without AGPLv3 source code sharing obligations

See LICENSE-COMMERCIAL.md for details and contact information.

### Full License Text

See the LICENSE file for the complete AGPLv3 license text.

### Your First Scan

```bash
# Index your codebase (one-time operation)
falconeye index /path/to/your/project

# Analyze for vulnerabilities
falconeye review /path/to/your/project

# Or do both in one command
falconeye scan /path/to/your/project
```

## Usage Examples

### Single File Analysis

```bash
$ falconeye scan ./myapp

███████╗ █████╗ ██╗      ██████╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗███████╗
██╔════╝██╔══██╗██║     ██╔════╝██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔════╝
█████╗  ███████║██║     ██║     ██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ █████╗  
██╔══╝  ██╔══██║██║     ██║     ██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔══╝  
██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████╗   ██║   ███████╗
╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝

                        Security Code Review
                     v2.0 - AI-Powered Analysis
                     by hardw00t & h4ckologic

Indexing codebase...
Indexed 127 files in 8.3s

Analyzing for vulnerabilities...
Found 12 potential issues

Results saved to: falconeye_reports/falconeye_myapp_20251113_130425.html
```

## Key Features

### AI-Powered Analysis
- **Semantic Code Understanding**: Goes beyond pattern matching to understand intent and data flow
- **RAG-Enhanced Context**: Retrieves similar code patterns from your entire codebase
- **Confidence Scoring**: AI rates its confidence in each finding
- **CWE Mapping**: Maps vulnerabilities to Common Weakness Enumeration

### Enhanced CLI Experience
- **ASCII Art Banner**: Stylish cyan-themed banner on every command
- **Rich Console Output**: Color-coded terminal output with progress indicators
- **Smart Error Messages**: Clear, actionable error messages with solutions
- **Graceful Degradation**: Continues analysis even when individual files fail

### Robust Processing
- **Advanced JSON Parsing**: Multi-layer escape sequence fixing for AI responses
- **Automatic Line Numbers**: Populates line numbers from source files
- **Context Expansion**: Automatically expands code snippets with surrounding context
- **Debug File Generation**: Saves problematic responses for troubleshooting

### Multiple Output Formats
- **Console**: Rich, color-coded terminal output
- **JSON**: Machine-readable format for CI/CD integration
- **HTML**: Interactive reports with executive summaries
- **SARIF**: Industry-standard format for security platforms

### Performance
- **Incremental Scanning**: Only re-analyzes changed files after initial scan
- **Parallel Processing**: Batch processing for faster analysis
- **Smart Caching**: Reuses embeddings and context when possible
- **Optimized Chunking**: Intelligent code segmentation for better context

```bash
# Human-readable console output
falconeye review src/ --format console

# Machine-readable JSON (auto-generates HTML report too)
falconeye review src/ --format json --output findings.json

# HTML report with interactive dashboard
falconeye review src/ --format html --output report.html

# SARIF for CI/CD integration
falconeye review src/ --format sarif --output results.sarif
```

**Default Behavior**: When no output file is specified, FalconEYE automatically saves both JSON and HTML reports to `./falconeye_reports/` with timestamps:
```bash
falconeye scan /path/to/project
# Generates:
# - falconeye_project_20251112_171500.json
# - falconeye_project_20251112_171500.html
```

### Project Management

```bash
# View all indexed projects
falconeye projects list

# Get detailed project statistics
falconeye projects info <project-id>

# Clean up old projects
falconeye projects delete <project-id>
```

## Configuration

FalconEYE uses a hierarchical configuration system. Configuration files are loaded in this order (later files override earlier ones):

1. Default config: `<install-dir>/config.yaml`
2. User config: `~/.falconeye/config.yaml`
3. Project config: `./falconeye.yaml`

Create `~/.falconeye/config.yaml` to customize settings:

```yaml
llm:
  provider: ollama
  model:
    analysis: qwen3-coder:30b      # AI model for security analysis
    embedding: embeddinggemma:300m  # Model for code embeddings
  base_url: http://localhost:11434
  timeout: 600                      # Request timeout in seconds

analysis:
  top_k_context: 5          # Number of similar code chunks to retrieve
  validate_findings: true    # Enable AI validation pass
  batch_size: 10            # Files to process in parallel

logging:
  level: INFO               # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: ./falconeye.log     # Log file path
  console: true             # Enable console logging
  rotation: daily           # Log rotation strategy
  retention_days: 30        # Days to retain logs
```

See the [default config.yaml](config.yaml) for all available options.

## Supported Languages

FalconEYE analyzes code in multiple languages with language-specific security knowledge:

**Currently Supported:**
Python • JavaScript • TypeScript • Go • Rust • C/C++ • Java • Dart • PHP

**Extensible Plugin System:**
Add new languages by implementing language-specific plugins with tailored security prompts.

## Understanding the Output

FalconEYE supports multiple output formats for different use cases:

### Console Format
Interactive terminal output with color-coded severity levels:
```
╭─ SQL Injection Vulnerability ────────────────────────────────╮
│ Severity: HIGH | CWE-89                                       │
│ File: app/database.py:42                                      │
│                                                               │
│ The function executes raw SQL with user input without        │
│ parameterization, allowing SQL injection attacks.            │
│                                                               │
│ Recommendation:                                               │
│ Use parameterized queries or an ORM to safely handle user    │
│ input in database operations.                                │
╰───────────────────────────────────────────────────────────────╯
```

### JSON Format
Machine-readable format for CI/CD integration and programmatic processing:
```json
{
  "findings": [
    {
      "id": "uuid",
      "issue": "SQL Injection Vulnerability",
      "severity": "high",
      "confidence": {"value": "high", "level": "high"},
      "location": {
        "file_path": "app/database.py",
        "line_start": 42,
        "line_end": 45
      },
      "code_snippet": "...",
      "reasoning": "...",
      "mitigation": "Use parameterized queries...",
      "cwe_id": "CWE-89"
    }
  ]
}
```

## CLI Command Reference

| Command | Description |
|---------|-------------|
| `falconeye index <path>` | Index codebase for analysis |
| `falconeye review <path>` | Analyze code for vulnerabilities |
| `falconeye scan <path>` | Index and review in one step |
| `falconeye scan <path> -v` | Scan with verbose output (full logs + LLM streaming) |
| `falconeye projects list` | Show all indexed projects |
| `falconeye projects info <id>` | Display project details |
| `falconeye projects delete <id>` | Delete a project and its data |
| `falconeye projects cleanup` | Remove orphaned project data |
| `falconeye info` | System and configuration information |

### Verbose Mode (`-v` or `--verbose`)

The verbose flag enables detailed output for better visibility into the analysis process:

**Normal Mode** (default):
- Clean progress bar showing file count and percentage
- Real-time findings display as they're detected
- Final summary with all results
- Minimal log output

**Verbose Mode** (`-v`):
- Full indexing logs (file processing, chunking, embedding generation)
- LLM thought process streaming (see AI analysis in real-time)
- All security analysis logs and details
- Detailed progress information
- Complete error stack traces if analysis fails

**Examples:**
```bash
# Normal mode - clean output
falconeye scan ./src

# Verbose mode - detailed output with LLM streaming
falconeye scan ./src -v

# Alternative verbose syntax
falconeye scan ./src --verbose
```

Run `falconeye --help` or `falconeye scan --help` for complete documentation.

### Areas for Contribution
- **Language Support**: Add support for new programming languages
- **Output Formats**: Implement new report formats (PDF, CSV, etc.)
- **HTML Templates**: Create custom report templates
- **Integrations**: Build integrations with security platforms
- **Performance**: Optimize analysis speed and memory usage
- **Documentation**: Improve guides and examples

### Pull Request Process
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Update documentation
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to your branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

- **Domain Layer**: Pure business logic for security analysis
- **Application Layer**: Orchestrates use cases and workflows
- **Infrastructure Layer**: Handles external systems (LLM, storage, parsing)
- **Adapters Layer**: User interfaces and output formatting

**Production-Ready Features:**

- Circuit breaker pattern prevents cascade failures
- Exponential backoff retry logic handles transient errors
- Structured JSON logging with correlation IDs
- Thread-safe context management

## Development

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run test suite
pytest

# Run integration tests (requires Ollama)
pytest tests/integration/ -v
```

## Frequently Asked Questions

**Q: Does my code get sent to external services?**
A: No. FalconEYE runs entirely locally using Ollama. Your code never leaves your machine.

**Q: How accurate is AI-based analysis compared to traditional scanners?**
A: FalconEYE complements traditional tools. It excels at finding context-dependent vulnerabilities and novel patterns that signature-based tools miss, while the AI validation reduces false positives.

**Q: How long does analysis take?**
A: Initial indexing depends on codebase size. Subsequent scans with smart re-indexing only process changed files, making them significantly faster.

**Q: Can I use different AI models?**
A: Yes. Configure any Ollama-compatible model in your config file.

**Q: How do I integrate this into CI/CD?**
A: Use SARIF output format which integrates with GitHub Security, GitLab, and most DevSecOps platforms.


## License

FalconEYE is dual-licensed:

**AGPLv3:** Free for non-commercial, educational, and open source use. See LICENSE file.

**Commercial:** Required for proprietary integration and commercial services. See LICENSE-COMMERCIAL.md.

Copyright (c) 2025 hardw00t & h4ckologic

---

## Quick Reference

### Common Commands
```bash
# Full scan (index + review)
falconeye scan /path/to/project

# Review only (requires prior indexing)
falconeye review /path/to/project

# Generate HTML report
falconeye review /path/to/project --format html --output report.html

# Filter by severity
falconeye review /path/to/project --severity high

# List indexed projects
falconeye projects list

# System information
falconeye info
```

### Output Locations
- **Reports**: `./falconeye_reports/`
- **Logs**: `./falconeye.log`
- **Config**: `~/.falconeye/config.yaml`
- **Debug Files**: `/tmp/falconeye_failed_response_*.txt`

**Built for security engineers who demand more than pattern matching.**

Version 2.0.0 | Python 3.12+ | Production Ready

By [hardw00t](https://github.com/hardw00t) & [h4ckologic](https://github.com/h4ckologic)
