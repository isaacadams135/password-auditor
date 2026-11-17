package com.github.isaacadams135.passwordauditor;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Strength result for one password. Entropy is the rough estimate
 * length * log2(alphabet), where the alphabet grows with the character classes
 * present: 26 lower, 52 upper+lower, 62 with digits, 72 with the 10 most
 * common symbols (!@#$%^&*()-). Crack time assumes an offline attacker at
 * 1e11 guesses/sec (fast hash, GPU rig), stops at half the keyspace, and
 * reports anything past ~1000 years as "centuries".
 */
public record PasswordCheck(int score, List<String> reasons, double entropyBits, String crackTime) {

    private static final double GUESSES_PER_SECOND = 1e11;

    public static PasswordCheck check(String password) {
        double bits = entropyBits(password);
        String crackTime = formatCrackTime(guessSeconds(bits));

        if (CommonPasswords.contains(normalize(password))) {
            return new PasswordCheck(0, List.of("common password"), bits, crackTime);
        }

        List<String> reasons = new ArrayList<>();
        int score = 0;

        if (password.length() >= 10) {
            score++;
        } else {
            reasons.add("too short");
        }
        if (password.length() >= 14) {
            score++;
        } else {
            reasons.add("under 14 characters");
        }

        int classes = classCount(password);
        if (classes >= 3) {
            score++;
        } else {
            reasons.add("only " + classes + " of 4 character classes");
        }

        String lower = password.toLowerCase(Locale.ROOT);
        boolean sequence = hasSequence(lower);
        boolean repeat = hasRepeat(lower);
        if (sequence) {
            reasons.add("sequence found");
        }
        if (repeat) {
            reasons.add("3+ repeated characters");
        }
        if (!sequence && !repeat) {
            score++;
        }
        if (sequence || repeat) {
            score = Math.min(score, 1);
        }

        return new PasswordCheck(Math.min(score, 4), List.copyOf(reasons), bits, crackTime);
    }

    /**
     * Lowercases and undoes common leet substitutions so p@ssw0rd and Password1
     * both reduce to forms present in the common list.
     */
    static String normalize(String password) {
        StringBuilder out = new StringBuilder(password.length());
        for (char c : password.toLowerCase(Locale.ROOT).toCharArray()) {
            out.append(switch (c) {
                case '@', '4' -> 'a';
                case '0' -> 'o';
                case '1', '!' -> 'i';
                case '3' -> 'e';
                case '$' -> 's';
                default -> c;
            });
        }
        return out.toString();
    }

    // cheap substring check, not a full keyboard-walk detector
    static boolean hasSequence(String lower) {
        return lower.contains("abc")
                || lower.contains("123")
                || lower.contains("qwerty")
                || lower.contains("asdf")
                || lower.contains("0123");
    }

    static boolean hasRepeat(String lower) {
        for (int i = 2; i < lower.length(); i++) {
            if (lower.charAt(i) == lower.charAt(i - 1) && lower.charAt(i) == lower.charAt(i - 2)) {
                return true;
            }
        }
        return false;
    }

    static double entropyBits(String password) {
        boolean[] present = presentClasses(password);
        int alphabet = (present[0] ? 26 : 0) + (present[1] ? 26 : 0)
                + (present[2] ? 10 : 0) + (present[3] ? 10 : 0);
        if (alphabet < 2) {
            return 0.0;
        }
        return password.length() * (Math.log(alphabet) / Math.log(2));
    }

    static String formatCrackTime(double seconds) {
        if (seconds < 60) {
            return unit(Math.round(seconds), "second");
        }
        if (seconds < 3600) {
            return unit(Math.round(seconds / 60), "minute");
        }
        if (seconds < 86400) {
            return unit(Math.round(seconds / 3600), "hour");
        }
        double days = seconds / 86400;
        if (days < 365) {
            return unit(Math.round(days), "day");
        }
        double years = days / 365;
        if (years >= 1000) {
            return "centuries";
        }
        return unit(Math.round(years), "year");
    }

    private static String unit(long n, String name) {
        return "about " + n + " " + name + (n == 1 ? "" : "s");
    }

    private static double guessSeconds(double bits) {
        // average case is half the keyspace
        return Math.pow(2, bits - 1) / GUESSES_PER_SECOND;
    }

    private static int classCount(String password) {
        boolean[] present = presentClasses(password);
        return (present[0] ? 1 : 0) + (present[1] ? 1 : 0) + (present[2] ? 1 : 0) + (present[3] ? 1 : 0);
    }

    private static boolean[] presentClasses(String password) {
        boolean[] present = new boolean[4]; // lower, upper, digit, symbol
        for (char c : password.toCharArray()) {
            if (Character.isLowerCase(c)) {
                present[0] = true;
            } else if (Character.isUpperCase(c)) {
                present[1] = true;
            } else if (Character.isDigit(c)) {
                present[2] = true;
            } else {
                present[3] = true;
            }
        }
        return present;
    }
}
