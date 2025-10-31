# secureghxst
Interactive terminal-based Security+ exam prep tool with 30 levels and 150 practice questions.  Learn cybersecurity through hacking scenarios instead of boring flashcards. Get a question wrong and restart  the entire level. Built for people who actually want to pass the exam.

Pass Security+ in 30 days using a Linux terminal hacking simulator. 150 questions covering all exam domains.

## What is this?

SecureGhxst is a terminal-based Security+ training tool that makes studying actually fun. You play through 30 levels of hacking scenarios, each with 5 questions. Get one wrong and you start the level over. Complete all 30 levels and you're ready for the real exam.

## Installation
```bash
git clone https://github.com/ibdtech/secureghxst
cd secureghxst
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install rich
python secureghxst.py
```

## How to play

Use real Linux commands to navigate and play:
```bash
ls                    # List available levels
cd level_01_NETWORK_RECONNAISSANCE  # Enter a level
cat README.md         # View game info
cat STUDY_PLAN.md     # See 30-day plan
stats                 # Check your progress
help                  # Show all commands
exit                  # Quit game
```

## Features

- 30 levels covering all Security+ domains
- 150 exam-style questions with detailed explanations
- Progress tracking and statistics
- Automatic level restart on wrong answers
- Must complete each level to unlock the next
- Terminal commands feel like real hacking

## What you'll learn

- Network security and protocols
- Cryptography and PKI
- Threats and vulnerabilities
- Identity and access management
- Security operations
- Governance and compliance
- Cloud and virtualization security
- Incident response
- Risk management

## Why this works

Most people fail Security+ because they memorize dumps instead of understanding concepts. This tool forces you to actually learn by:

1. Making you answer 5 questions perfectly to pass each level
2. Restarting the entire level if you get one wrong
3. Explaining every answer so you understand why
4. Covering real exam scenarios, not just theory

## Requirements

- Python 3.6+
- rich library

## Support

If this helped you pass Security+, buy me a coffee:

CashApp: $Ghxstsh3ll

## License

MIT

Built by ghxstsh3ll

