#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <regex>
#include "httplib.h"

using namespace std;

// ---------- TRIE IMPLEMENTATION ----------
struct TrieNode {
    map<char, TrieNode*> children;
    bool endOfWord = false;
};

class Trie {
public:
    TrieNode* root;
    Trie() { root = new TrieNode(); }

    void insert(const string& word) {
        TrieNode* curr = root;
        for (char c : word) {
            if (!curr->children[c])
                curr->children[c] = new TrieNode();
            curr = curr->children[c];
        }
        curr->endOfWord = true;
    }

    bool search(const string& word) {
        TrieNode* curr = root;
        for (char c : word) {
            if (!curr->children[c]) return false;
            curr = curr->children[c];
        }
        return curr->endOfWord;
    }
};

// ---------- BUILD WEAK PATTERN TRIE ----------
Trie buildWeakTrie() {
    Trie t;
    vector<string> weak = {"1234", "password", "admin", "qwerty", "aaaa"};
    for (auto &w : weak)
        t.insert(w);
    return t;
}

// ---------- KMP STRING MATCHING ----------
vector<int> buildLPS(const string& pat) {
    vector<int> lps(pat.size(), 0);
    for (int i = 1, len = 0; i < pat.size(); ) {
        if (pat[i] == pat[len])
            lps[i++] = ++len;
        else if (len)
            len = lps[len - 1];
        else
            lps[i++] = 0;
    }
    return lps;
}

bool KMPSearch(const string& text, const string& pat) {
    vector<int> lps = buildLPS(pat);
    for (int i = 0, j = 0; i < text.size(); ) {
        if (text[i] == pat[j]) {
            i++; j++;
            if (j == pat.size()) return true;
        } else if (j) {
            j = lps[j - 1];
        } else {
            i++;
        }
    }
    return false;
}

// ---------- BRUTE FORCE STRING MATCHING ----------
bool bruteForceMatch(const string& text, const string& pat) {
    for (int i = 0; i <= text.size() - pat.size(); i++) {
        int j = 0;
        while (j < pat.size() && text[i + j] == pat[j])
            j++;
        if (j == pat.size()) return true;
    }
    return false;
}

// ---------- GREEDY PASSWORD ANALYZER ----------
map<string, string> analyzePassword(const string& pass) {
    Trie trie = buildWeakTrie();
    int score = 0;
    string suggestion = "";

    // Length check
    if (pass.length() >= 12) score += 2;
    else if (pass.length() >= 8) score += 1;
    else suggestion += "Use at least 8 characters. ";

    bool up=false, low=false, dig=false, sym=false;
    for (char c : pass) {
        if (isupper(c)) up = true;
        if (islower(c)) low = true;
        if (isdigit(c)) dig = true;
        if (!isalnum(c)) sym = true;
    }

    if (up) score++; else suggestion += "Add uppercase letters. ";
    if (low) score++; else suggestion += "Add lowercase letters. ";
    if (dig) score++; else suggestion += "Add digits. ";
    if (sym) score++; else suggestion += "Add symbols. ";

    // Regex repetition check
    regex repeat("(.)\\1{2,}");
    if (!regex_search(pass, repeat)) score++;
    else suggestion += "Avoid repeated characters. ";

    // ---------- STRING MATCHING CHECKS ----------
    vector<string> weakPatterns = {"1234", "password", "admin", "qwerty"};

    bool weakFound = false;
    for (auto &w : weakPatterns) {
        if (
            trie.search(w) && 
            (KMPSearch(pass, w) || bruteForceMatch(pass, w))
        ) {
            weakFound = true;
            break;
        }
    }

    if (weakFound)
        suggestion += "Remove common weak patterns. ";
    else
        score++;

    string strength;
    if (score <= 3) strength = "Weak";
    else if (score <= 6) strength = "Moderate";
    else strength = "Strong";

    return {
        {"strength", strength},
        {"suggestion", suggestion}
    };
}

// ---------- HTTP SERVER ----------
int main() {
    httplib::Server server;

    server.set_default_headers({
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Methods", "POST, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type"}
    });

    server.Options("/analyze", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
    });

    server.Post("/analyze", [](const httplib::Request& req, httplib::Response& res) {
        string password = req.get_param_value("password");

        if (password.empty()) {
            res.set_content(
                "{ \"strength\": \"N/A\", \"suggestion\": \"Enter a password.\" }",
                "application/json"
            );
            return;
        }

        auto result = analyzePassword(password);

        string json = "{ \"strength\": \"" + result["strength"] +
                      "\", \"suggestion\": \"" + result["suggestion"] + "\" }";

        res.set_content(json, "application/json");
    });

    cout << "Server running on http://localhost:5000\n";
    server.listen("0.0.0.0", 5000);
}
