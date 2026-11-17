package com.github.isaacadams135.passwordauditor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class Main {

    private static final String USAGE = """
        usage: password-auditor [options] <file>

        reads one password per line (blank lines and # comments are skipped).
        passwords are never printed unless you pass --show, and nothing is
        sent anywhere - the whole audit runs offline on your machine.

        options:
          --policy    check each line against policy rules instead of scoring
                      (exit 1 if any line fails)
          --show      print the actual password instead of "line N"
          -h, --help  show this help
        """;

    private Main() {
    }

    public static void main(String[] args) {
        Options opts;
        try {
            opts = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.err.println(USAGE);
            System.exit(2);
            return;
        }

        if (opts.help()) {
            System.out.println(USAGE);
            return;
        }

        List<String> lines;
        try {
            lines = Files.readAllLines(opts.file(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            System.err.println("error: could not read " + opts.file() + ": " + e.getMessage());
            System.exit(1);
            return;
        }

        List<Entry> entries = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            entries.add(new Entry(i + 1, line));
        }

        System.out.printf("file   %s%n", opts.file());
        System.out.printf("mode   %s%n", opts.policy() ? "policy" : "strength");
        System.out.println();

        if (entries.isEmpty()) {
            System.out.println("no passwords found");
            return;
        }

        if (opts.policy()) {
            runPolicy(entries, opts.show());
            return;
        }
        runStrength(entries, opts.show());
    }

    private static void runStrength(List<Entry> entries, boolean show) {
        int[] byScore = new int[5];
        int weakestLine = -1;
        int weakestScore = 5;

        for (Entry entry : entries) {
            PasswordCheck result = PasswordCheck.check(entry.password());
            byScore[result.score()]++;
            if (result.score() < weakestScore) {
                weakestScore = result.score();
                weakestLine = entry.line();
            }
            String label = show ? entry.password() : "line " + entry.line();
            String reasons = result.reasons().isEmpty()
                    ? ""
                    : " [" + String.join(", ", result.reasons()) + "]";
            System.out.printf("%-12s score %d/4%-46s entropy %3.0f bits (~%s)%n",
                    label, result.score(), reasons, result.entropyBits(), result.crackTime());
        }

        System.out.println();
        System.out.printf("scores  0:%d  1:%d  2:%d  3:%d  4:%d%n",
                byScore[0], byScore[1], byScore[2], byScore[3], byScore[4]);
        System.out.printf("weakest line %d (score %d)%n", weakestLine, weakestScore);
    }

    private static void runPolicy(List<Entry> entries, boolean show) {
        int passed = 0;
        int failed = 0;

        for (Entry entry : entries) {
            List<String> fails = Policy.failures(entry.password());
            String label = show ? entry.password() : "line " + entry.line();
            if (fails.isEmpty()) {
                passed++;
                System.out.printf("%-12s ok%n", label);
            } else {
                failed++;
                System.out.printf("%-12s FAIL  [%s]%n", label, String.join(", ", fails));
            }
        }

        System.out.println();
        System.out.printf("passed %d, failed %d%n", passed, failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    record Entry(int line, String password) {
    }

    record Options(Path file, boolean policy, boolean show, boolean help) {

        static Options parse(String[] args) {
            boolean policy = false;
            boolean show = false;
            boolean help = false;
            Path file = null;

            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "-h", "--help" -> help = true;
                    case "--policy" -> policy = true;
                    case "--show" -> show = true;
                    default -> {
                        if (arg.startsWith("-")) {
                            throw new IllegalArgumentException("unknown option: " + arg);
                        }
                        if (file != null) {
                            throw new IllegalArgumentException("unexpected argument: " + arg);
                        }
                        file = Path.of(arg);
                    }
                }
            }

            if (help) {
                return new Options(null, false, false, true);
            }
            if (file == null) {
                throw new IllegalArgumentException("missing file");
            }
            return new Options(file, policy, show, false);
        }
    }
}
