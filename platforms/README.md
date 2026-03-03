# Security Audit — Multi-Platform Prompts

Same security audit, adapted for every major AI coding assistant.

| Platform | File | How to use |
|---|---|---|
| **ChatGPT** | `chatgpt/security-audit-gpt.txt` | Paste into Custom GPT → Instructions |
| **Gemini** | `gemini/security-audit-gem.txt` | Paste into Gemini → Create a Gem → Instructions |
| **Cursor** | `cursor/security-audit.mdc` | Copy to `.cursor/rules/security-audit.mdc` in your project |
| **GitHub Copilot** | `copilot/copilot-instructions.md` | Copy to `.github/copilot-instructions.md` in your project |
| **Windsurf** | `windsurf/.windsurfrules` | Copy to `.windsurfrules` at the root of your project |

---

## ChatGPT — Create a Custom GPT

1. Go to [chatgpt.com](https://chatgpt.com) → Explore GPTs → Create
2. Name: `Security Audit`
3. Instructions: paste the full content of `chatgpt/security-audit-gpt.txt`
4. Capabilities: enable Code Interpreter (for file uploads)
5. Save and share

**Usage**: Ask the GPT to "audit my project" and paste your code files.

---

## Gemini — Create a Gem

1. Go to [gemini.google.com](https://gemini.google.com) → Gems → New Gem
2. Name: `Security Audit`
3. Instructions: paste the full content of `gemini/security-audit-gem.txt`
4. Save

**Usage**: Open the Gem and paste your code files for analysis.

---

## Cursor — Project Rule

1. Create the directory: `mkdir -p .cursor/rules`
2. Copy the file: `cp security-audit.mdc .cursor/rules/security-audit.mdc`
3. The rule activates automatically on the file types listed in `globs`

Or ask Cursor directly: "Apply @security-audit to this file"

**Usage**: Cursor will flag security issues as you code. Ask "audit this file for security issues" to trigger a full review.

---

## GitHub Copilot — Workspace Instructions

1. Copy the file to your project: `cp copilot-instructions.md .github/copilot-instructions.md`
2. Commit and push
3. Copilot Chat will now apply these security rules in your repository

**Usage**: Copilot will automatically flag security issues during code suggestions. In Copilot Chat, ask "review this file for security vulnerabilities".

---

## Windsurf — Project Rules

1. Copy the file to your project root: `cp .windsurfrules /path/to/your/project/.windsurfrules`
2. Windsurf automatically picks up `.windsurfrules` from the workspace root

**Usage**: Type `/security-audit` or ask "find security issues in this project" in Windsurf Chat.

---

## Key differences between platforms

| Feature | Claude Code | ChatGPT | Gemini | Cursor | Copilot | Windsurf |
|---|---|---|---|---|---|---|
| File system access | ✅ Direct | ❌ Paste only | ❌ Paste only | ✅ Workspace | ✅ Workspace | ✅ Workspace |
| Run bash commands | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| Parallel sub-agents | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Best for | Full projects | Code review | Code review | Active coding | Active coding | Active coding |
