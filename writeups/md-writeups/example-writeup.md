# Example Writeup

**Author:** Jordan Lanham  
**Event:** Example CTF 2025  
**Category:** Misc  
**Date:** Jan 15, 2025  
**Read Time:** 8 minutes

---

## Overview

This is a template writeup showing how to format your CTF solution writeups. Replace this entire file with your actual writeup content.

## Challenge Description

Provide a brief description of the challenge here. What was the objective? What were the constraints?

Example: 
> We were given a file called `challenge.txt` and needed to find the hidden flag using basic cryptography.

## Initial Analysis

Start by describing what you found when you first examined the challenge:

- What files or services were provided?
- What were the initial observations?
- What tools did you use for reconnaissance?

## Solution Approach

Walk through your step-by-step approach to solving the challenge:

### Step 1: Reconnaissance
Describe your initial exploration of the challenge. What did you discover?

### Step 2: Vulnerability Identification
What vulnerability or weakness did you find?

### Step 3: Exploitation
How did you exploit the vulnerability? What was your attack strategy?

### Step 4: Flag Extraction
How did you get the final flag?

## Code / Exploit

Include your solution code here:

```python
#!/usr/bin/env python3
# Example solution code

def solve_challenge(input_file):
    with open(input_file, 'r') as f:
        data = f.read()
    
    # Your solution logic here
    return flag

if __name__ == "__main__":
    flag = solve_challenge("challenge.txt")
    print(f"Flag: {flag}")
```

Or in another language:

```bash
#!/bin/bash
# Bash solution example

echo "Processing challenge..."
flag=$(cat challenge.txt | tr 'a-z' 'n-za-m')  # ROT13 example
echo "Flag: $flag"
```

## Technical Details

Explain any important technical concepts or tricks used:

- **Encryption/Decryption:** What algorithm was used?
- **Encoding:** Base64, hex, ASCII?
- **Protocol:** HTTP, SSH, custom?
- **Vulnerability:** SQL injection, XSS, buffer overflow?

## Key Insights

What did you learn from this challenge? What techniques could be reused?

- This type of challenge teaches you about [X concept]
- A useful tool to remember is [Y tool]
- Watch out for [Z common mistake]

## The Flag

```
flag{this_is_the_example_flag_format}
```

## Resources

Links to helpful resources used in solving this challenge:

- [Resource 1](https://example.com)
- [Resource 2](https://example.com)
- [Related CVE](https://example.com)

---

**Tips for writing great writeups:**
- Be clear and verbose - assume the reader hasn't seen the challenge
- Include code snippets and command examples
- Explain the "why" not just the "what"
- Use headers and formatting to organize your thoughts
