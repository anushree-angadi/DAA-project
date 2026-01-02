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
    Trie() { root = new TrieNode(); }

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
   BRUTE FORCE STRING MATCHING
   ===================================================== */
bool bruteForceMatch(const string& text, const string& pattern) {
    int n = text.length();
    int m = pattern.length();
    for (int i = 0; i <= n - m; i++) {
        int j = 0;
        while (j < m && text[i + j] == pattern[j]) j++;
        if (j == m) return true;
    }
    return false;
}

/* =====================================================
   KMP STRING MATCHING
   ===================================================== */
vector<int> computeLPS(const string& pattern) {
    int m = pattern.length();
    vector<int> lps(m, 0);
    for (int i = 1, len = 0; i < m;) {
        if (pattern[i] == pattern[len]) lps[i++] = ++len;
        else if (len != 0) len = lps[len - 1];
        else lps[i++] = 0;
    }
    return lps;
}

bool KMPMatch(const string& text, const string& pattern) {
    vector<int> lps = computeLPS(pattern);
    int i = 0, j = 0;
    while (i < text.length()) {
        if (text[i] == pattern[j]) { i++; j++; }
        if (j == pattern.length()) return true;
        else if (i < text.length() && text[i] != pattern[j]) {
            if (j != 0) j = lps[j - 1];
            else i++;
        }
    }
    return false;
}

/* =====================================================
   PASSWORD ANALYSIS (GREEDY HEURISTIC)
   ===================================================== */

pair<string, string> analyzePassword(const string& pass) {
    Trie trie;
    vector<string> weakPatterns = {"password", "admin", "qwerty", "1234", "1111"};
    for (auto w : weakPatterns) trie.insert(w);

    int score = 0;
    string suggestion = "";

    // Length check
    if (pass.length() >= 12) score += 2;
    else if (pass.length() >= 8) score += 1;
    else suggestion += "Use at least 8 characters. ";

    // Character variety
    bool up=false, low=false, dig=false, sym=false;
    for (char c : pass) {
        if (isupper(c)) up=true;
        else if (islower(c)) low=true;
        else if (isdigit(c)) dig=true;
        else sym=true;
    }
    if(up) score++; else suggestion += "Add uppercase letters. ";
    if(low) score++; else suggestion += "Add lowercase letters. ";
    if(dig) score++; else suggestion += "Add numbers. ";
    if(sym) score++; else suggestion += "Add symbols (#, @, !). ";

    // Repeated chars
    regex repeat("(.)\\1{2,}");
    if (regex_search(pass, repeat)) suggestion += "Avoid repeating characters. ";
    else score++;

    // Weak pattern detection (Trie + Brute Force + KMP)
    bool hasWeakPattern = false;
    string lowerPass = pass;
    transform(lowerPass.begin(), lowerPass.end(), lowerPass.begin(), ::tolower);

    for (auto pattern : weakPatterns) {
        if (trie.search(pattern) || bruteForceMatch(lowerPass, pattern) || KMPMatch(lowerPass, pattern)) {
            hasWeakPattern = true;
            break;
        }
    }

    if (hasWeakPattern) suggestion += "Remove common weak patterns like '1234'. ";
    else score++;

    // Strength
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
            res.set_content("{ \"strength\": \"N/A\", \"suggestion\": \"Password required.\" }", "application/json");
            return;
        }
        string password = req.get_param_value("password");
        auto result = analyzePassword(password);

        string json = "{ \"strength\": \"" + result.first + "\", \"suggestion\": \"" + result.second + "\" }";
        res.set_content(json, "application/json");
    });

    cout << "Server running at http://localhost:5000\n";
    server.listen("0.0.0.0", 5000);
    return 0;
}