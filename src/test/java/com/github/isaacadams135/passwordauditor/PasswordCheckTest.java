package com.github.isaacadams135.passwordauditor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class PasswordCheckTest {

    @Test
    void commonPasswordScoresZero() {
        PasswordCheck result = PasswordCheck.check("password");
        assertEquals(0, result.score());
        assertEquals(List.of("common password"), result.reasons());
    }

    @Test
    void leetSpellingOfCommonPasswordScoresZero() {
        PasswordCheck result = PasswordCheck.check("p@ssw0rd");
        assertEquals(0, result.score());
        assertTrue(result.reasons().contains("common password"));
    }

    @Test
    void strongPasswordScoresAtLeastThree() {
        PasswordCheck result = PasswordCheck.check("Tr0ub4dor&3");
        assertTrue(result.score() >= 3, "score was " + result.score());
    }

    @Test
    void repeatedRunCapsScoreAtOne() {
        PasswordCheck result = PasswordCheck.check("aaaabbbbcccc");
        assertEquals(1, result.score());
        assertTrue(result.reasons().contains("3+ repeated characters"));
    }

    @Test
    void sequenceCapsScoreAtOne() {
        PasswordCheck result = PasswordCheck.check("abcdefghijkl");
        assertEquals(1, result.score());
        assertTrue(result.reasons().contains("sequence found"));
    }

    @Test
    void entropyGrowsWithLength() {
        PasswordCheck shortPwd = PasswordCheck.check("abcdefg");
        PasswordCheck longPwd = PasswordCheck.check("abcdefgABCDEFGH123!@#$");
        assertTrue(longPwd.entropyBits() > shortPwd.entropyBits() * 2,
                longPwd.entropyBits() + " vs " + shortPwd.entropyBits());
    }

    @Test
    void crackTimeFormatsKnownValues() {
        assertEquals("about 0 seconds", PasswordCheck.formatCrackTime(0.002));
        assertEquals("about 1 second", PasswordCheck.formatCrackTime(1.2));
        assertEquals("about 2 minutes", PasswordCheck.formatCrackTime(90));
        assertEquals("about 2 hours", PasswordCheck.formatCrackTime(7_200));
        assertEquals("about 3 days", PasswordCheck.formatCrackTime(3 * 86_400));
        assertEquals("about 5 years", PasswordCheck.formatCrackTime(5 * 365 * 86_400.0));
        assertEquals("centuries", PasswordCheck.formatCrackTime(1e18));
    }

    @Test
    void policyFailsShortCommonPasswordWithoutSymbol() {
        assertEquals(List.of("length>=12", "has symbol", "not common"),
                Policy.failures("Password1"));
        assertTrue(Policy.failures("Sunset!OverMountains#2024").isEmpty());
    }
}
