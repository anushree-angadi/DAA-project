#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <algorithm>
#include <cctype>
#include "httplib.h"

using namespace std;

/* =====================================================
   TRIE DATA STRUCTURE FOR WEAK PATTERN STORAGE
   ===================================================== */

struct TrieNode {
    TrieNode* children[26];
    bool isEnd;

    TrieNode() {
        isEnd = false;
        for (int i = 0; i < 26; i++)
            children[i] = nullptr;
    }
};

class Trie {
private:
    TrieNode* root;

public:
    Trie() {
        root = new TrieNode();
    }

    void insert(const string& word) {
        TrieNode* curr = root;
        for (char c : word) {
            int idx = c - 'a';
            if (!curr->children[idx])
                curr->children[idx] = new TrieNode();
            curr = curr->children[idx];
        }
        curr->isEnd = true;
    }

    bool search(const string& word) {
        TrieNode* curr = root;
        for (char c : word) {
            int idx = c - 'a';
            if (!curr->children[idx])
                return false;
            curr = curr->children[idx];
        }
        return curr->isEnd;
    }
};

/* =====================================================
   RABIN–KARP STRING MATCHING
   ===================================================== */

bool rabinKarpMatch(const string& text, const string& pattern) {
    int n = text.length();
    int m = pattern.length();
    if (m > n) return false;

    const int base = 256;
    const int mod = 101;

    int h = 1;
    for (int i = 0; i < m - 1; i++)
        h = (h * base) % mod;

    int pHash = 0, tHash = 0;

    for (int i = 0; i < m; i++) {
        pHash = (base * pHash + pattern[i]) % mod;
        tHash = (base * tHash + text[i]) % mod;
    }

    for (int i = 0; i <= n - m; i++) {
        if (pHash == tHash) {
            if (text.substr(i, m) == pattern)
                return true;
        }

        if (i < n - m) {
            tHash = (base * (tHash - text[i] * h) + text[i + m]) % mod;
            if (tHash < 0) tHash += mod;
        }
    }
    return false;
}

/* =====================================================
   PASSWORD ANALYSIS (GREEDY HEURISTIC)
   ===================================================== */

pair<string, string> analyzePassword(const string& password) {

    int score = 0;
    string suggestion = "";

    /* ---------- Greedy Length Check ---------- */
    if (password.length() >= 12) score += 2;
    else if (password.length() >= 8) score += 1;
    else suggestion += "Use at least 8 characters. ";

    /* ---------- Character Variety ---------- */
    bool upper = false, lower = false, digit = false, symbol = false;

    for (char c : password) {
        if (isupper(c)) upper = true;
        else if (islower(c)) lower = true;
        else if (isdigit(c)) digit = true;
        else symbol = true;
    }

    if (upper) score++; else suggestion += "Add uppercase letters. ";
    if (lower) score++; else suggestion += "Add lowercase letters. ";
    if (digit) score++; else suggestion += "Add digits. ";
    if (symbol) score++; else suggestion += "Add special symbols. ";

    /* ---------- Regex for Repeated Characters ---------- */
    regex repeat("(.)\\1{2,}");
    if (regex_search(password, repeat)) {
        suggestion += "Avoid repeated characters. ";
    } else {
        score++;
    }

    /* ---------- Weak Pattern Detection ---------- */
    Trie trie;
    vector<string> weakPatterns = {
        "password", "admin", "qwerty", "1234", "1111"
    };

    for (string w : weakPatterns)
        trie.insert(w);

    bool weakFound = false;
    string lowerPass = password;
    transform(lowerPass.begin(), lowerPass.end(), lowerPass.begin(), ::tolower);

    for (const string& pattern : weakPatterns) {
        if (rabinKarpMatch(lowerPass, pattern) || trie.search(pattern)) {
            weakFound = true;
            break;
        }
    }

    if (weakFound)
        suggestion += "Avoid common weak patterns like '1234' or 'password'. ";
    else
        score++;

    /* ---------- Strength Classification ---------- */
    string strength;
    if (score <= 3) strength = "Weak";
    else if (score <= 6) strength = "Moderate";
    else strength = "Strong";

    return {strength, suggestion};
}

/* =====================================================
   HTTP SERVER
   ===================================================== */

int main() {
    httplib::Server server;

    server.set_default_headers({
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Methods", "GET, POST, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type"}
    });

    server.Options("/analyze", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
    });

    server.Post("/analyze", [](const httplib::Request& req, httplib::Response& res) {

        if (!req.has_param("password")) {
            res.set_content(
                "{ \"strength\": \"N/A\", \"suggestion\": \"Password required.\" }",
                "application/json"
            );
            return;
        }

        string password = req.get_param_value("password");
        auto result = analyzePassword(password);

        string json =
            "{ \"strength\": \"" + result.first +
            "\", \"suggestion\": \"" + result.second + "\" }";

        res.set_content(json, "application/json");
    });

    cout << "Server running at http://localhost:5000\n";
    server.listen("0.0.0.0", 5000);
    return 0;
}