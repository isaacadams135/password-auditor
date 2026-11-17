package com.github.isaacadams135.passwordauditor;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Pass/fail rules for a password policy, stricter than the 0-4 score. */
final class Policy {

    static final int MIN_LENGTH = 12;

    private Policy() {
    }

    /** Empty list means the password passed every rule. */
    static List<String> failures(String password) {
        List<String> fails = new ArrayList<>();

        if (password.length() < MIN_LENGTH) {
            fails.add("length>=" + MIN_LENGTH);
        }

        boolean[] present = new boolean[4]; // upper, lower, digit, symbol
        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                present[0] = true;
            } else if (Character.isLowerCase(c)) {
                present[1] = true;
            } else if (Character.isDigit(c)) {
                present[2] = true;
            } else {
                present[3] = true;
            }
        }
        if (!present[0]) {
            fails.add("has upper");
        }
        if (!present[1]) {
            fails.add("has lower");
        }
        if (!present[2]) {
            fails.add("has digit");
        }
        if (!present[3]) {
            fails.add("has symbol");
        }

        if (CommonPasswords.contains(PasswordCheck.normalize(password))) {
            fails.add("not common");
        }

        String lower = password.toLowerCase(Locale.ROOT);
        if (PasswordCheck.hasSequence(lower)) {
            fails.add("no sequence");
        }
        if (PasswordCheck.hasRepeat(lower)) {
            fails.add("no repeat");
        }
        return fails;
    }
}
