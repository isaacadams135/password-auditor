# password-auditor

Offline auditor for password lists: one password per line, each scored 0-4
with plain-English reasons, or checked pass/fail against a small password
policy. I built it while writing up NIST password guidance (SP 800-63B) for an
internal audit - I wanted a way to look at training-exercise dumps without
pasting them into any website. Everything runs locally: passwords are never
printed unless you pass `--show`, and nothing leaves the machine.

## Features

- Scores each password 0-4 with reasons (too short, common password, sequence, ...)
- Normalizes leet speak (@, 0, 1, 3, 4, $, !) before matching ~125 common passwords
- Entropy estimate plus an offline crack-time guess (1e11 guesses/sec)
- `--policy` mode: pass/fail on length, character classes, common/sequence/repeat
  rules; exits 1 if any line fails
- Passwords print as `line N` unless you pass `--show`
- Skips blank lines and `#` comments; no network calls, no runtime dependencies

## Build

Requires JDK 21+.

```bash
./gradlew build
./gradlew jar
```

On Windows use `gradlew.bat`.

## Usage

```bash
java -jar build/libs/password-auditor-1.0.0.jar samples/passwords.txt
```

Real output on the sample file (strength mode):

```
file   samples\passwords.txt
mode   strength

line 2       score 0/4 [common password]                             entropy  38 bits (~about 1 second)
line 3       score 0/4 [common password]                             entropy  20 bits (~about 0 seconds)
line 4       score 0/4 [common password]                             entropy  28 bits (~about 0 seconds)
line 5       score 0/4 [common password]                             entropy  33 bits (~about 0 seconds)
line 6       score 0/4 [common password]                             entropy  54 bits (~about 19 hours)
line 8       score 3/4 [under 14 characters]                         entropy  68 bits (~about 43 years)
line 9       score 3/4 [only 2 of 4 character classes]               entropy 145 bits (~centuries)
line 10      score 3/4 [under 14 characters]                         entropy  80 bits (~centuries)
line 11      score 4/4                                               entropy 154 bits (~centuries)
line 12      score 1/4 [under 14 characters, only 1 of 4 character classes, 3+ repeated characters] entropy  56 bits (~about 6 days)
line 13      score 4/4                                               entropy  93 bits (~centuries)

scores  0:5  1:1  2:0  3:3  4:2
weakest line 2 (score 0)
```

Policy mode on the same file (exit code 1, since failures were found):

```
file   samples\passwords.txt
mode   policy

line 2       FAIL  [length>=12, has upper, has digit, has symbol, not common]
line 3       FAIL  [length>=12, has upper, has lower, has symbol, not common, no sequence]
line 4       FAIL  [length>=12, has upper, has digit, has symbol, not common, no sequence]
line 5       FAIL  [length>=12, has upper, has digit, has symbol, not common]
line 6       FAIL  [length>=12, has symbol, not common]
line 8       FAIL  [length>=12]
line 9       FAIL  [has upper, has digit]
line 10      ok
line 11      ok
line 12      FAIL  [has upper, has digit, has symbol, no repeat]
line 13      ok

passed 3, failed 8
```

Add `--show` to print the actual password in the first column instead of
`line N`. Exit codes: 0 clean, 1 file error or policy failures, 2 usage error.

## How it works

Each password is lowercased and leet-normalized, then matched against a
built-in common-password list; hits score 0 with the reason "common password".
Otherwise points come from length (>=10, >=14), at least 3 of 4 character
classes, and no keyboard sequences or 3+ character runs - sequences and runs
cap the score at 1. Entropy is length * log2(alphabet) with the alphabet
growing by which classes are present, and crack time is half the keyspace at
1e11 guesses/sec, with anything past ~1000 years shown as "centuries".

## Only use it on stuff you're allowed to

Only audit password lists you are authorized to handle (your own exercise
data, exports from your own audit).

## License

MIT
