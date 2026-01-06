#!/usr/bin/env python3
import re
import sys

def clean_go_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    lines = content.split('\n')
    result = []
    skip_until_package = True
    in_block = False
    
    for i, line in enumerate(lines):
        # Skip MIT license header at top
        if skip_until_package:
            if line.startswith('package '):
                skip_until_package = False
            else:
                continue
        
        # Skip block comments that aren't doc comments
        if '/*' in line and not (i > 0 and lines[i-1].strip().endswith('=')):
            in_block = True
        if in_block:
            result.append(line)
            if '*/' in line:
                in_block = False
            continue
        
        # Skip redundant inline comments (e.g., "x = 1 // set x")
        if '//' in line:
            code_part = line.split('//')[0].strip()
            comment_part = line.split('//', 1)[1].strip()
            
            # Keep meaningful comments
            if any(kw in comment_part.lower() for kw in ['todo', 'fixme', 'bug', 'hack', 'warning', 'note']):
                result.append(line)
            elif code_part and len(comment_part) < 20 and not any(c.isupper() for c in comment_part[0]):
                # Skip short, lowercase comments (likely redundant)
                result.append(code_part)
            else:
                result.append(line)
        else:
            result.append(line)
    
    with open(filepath, 'w') as f:
        f.write('\n'.join(result))
    print(f"Cleaned {filepath}")

if __name__ == '__main__':
    import glob
    for f in glob.glob('/root/transfer.ng/**/*.go', recursive=True):
        clean_go_file(f)
