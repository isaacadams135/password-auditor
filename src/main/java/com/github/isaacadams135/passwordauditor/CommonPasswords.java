package com.github.isaacadams135.passwordauditor;

import java.util.HashSet;
import java.util.Set;

/**
 * Small embedded list of well-known passwords - the ones that sit at the top
 * of every breach dump. Entries are normalized the same way as input, so leet
 * spellings like p@ssw0rd and Password1 still match.
 */
final class CommonPasswords {

    private static final String[] RAW = {
        "password", "password1", "password123", "123456", "1234567",
        "12345678", "123456789", "1234567890", "111111", "000000",
        "121212", "123123", "123321", "654321", "qwerty",
        "qwertyuiop", "qwerty123", "asdfgh", "asdfghjkl", "zxcvbn",
        "zxcvbnm", "letmein", "letmein1", "admin", "admin123",
        "administrator", "welcome", "welcome1", "welcome123", "monkey",
        "monkey123", "dragon", "dragon123", "football", "football1",
        "iloveyou", "iloveyou1", "princess", "princess1", "master",
        "master123", "shadow", "shadow123", "superman", "superman1",
        "batman", "batman1", "trustno1", "starwars", "starwars1",
        "whatever", "nopassword", "sunshine", "sunshine1", "michael",
        "jennifer", "jordan", "harley", "ranger", "hunter",
        "buster", "soccer", "hockey", "killer", "george",
        "charlie", "andrew", "thomas", "jessica", "daniel",
        "login", "login1", "abc123", "abcd1234", "pass123",
        "test", "test1", "test123", "guest", "guest123",
        "default", "changeme", "changeme123", "secret", "secret1",
        "secret123", "hello", "hello123", "freedom", "freedom1",
        "baseball", "corvette", "mercedes", "merlin", "matrix",
        "oracle", "system", "access", "access1", "internet",
        "computer", "service", "sesame", "orange", "pepper",
        "summer", "winter", "spring", "autumn", "flower",
        "rainbow", "magic", "love", "love123", "lovely",
        "babygirl", "babyboy", "sweetie", "angel", "heaven",
        "mustang", "silver", "golden", "diamond", "crystal",
        "purple", "joshua", "amanda", "nicole", "robert",
        "richard", "helpme", "azerty", "azertyuiop", "passwort"
    };

    private static final Set<String> LIST = normalizeAll();

    private CommonPasswords() {
    }

    static boolean contains(String normalized) {
        return LIST.contains(normalized);
    }

    private static Set<String> normalizeAll() {
        Set<String> set = new HashSet<>(RAW.length);
        for (String entry : RAW) {
            set.add(PasswordCheck.normalize(entry));
        }
        return set;
    }
}
