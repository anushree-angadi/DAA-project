#include <iostream>
#include <regex>
#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include "httplib.h"
using namespace std;

// ---------- Trie Node for Weak Pattern Detection ----------
struct TrieNode {
    map<char, TrieNode*> children;
    bool endOfWord = false;
};

class Trie {
public:
    TrieNode* root;
    Trie() { root = new TrieNode(); }

    void insert(string word) {
        TrieNode* current = root;
        for (char c : word) {
            if (!current->children[c])
                current->children[c] = new TrieNode();
            current = current->children[c];
        }
        current->endOfWord = true;
    }

    bool search(string word) {
        TrieNode* current = root;
        for (char c : word) {
            if (!current->children[c]) return false;
            current = current->children[c];
        }
        return current->endOfWord;
    }
};

// ---------- Build Weak Pattern Trie ----------
Trie buildWeakPatternTrie() {
    Trie t;
    vector<string> weak = {"1234", "password", "admin", "aaaa", "qwerty"};
    for (string w : weak) t.insert(w);
    return t;
}

// ---------- Password Strength Analyzer ----------
map<string, string> analyzePassword(string pass) {
    Trie trie = buildWeakPatternTrie();
    int score = 0;
    string suggestion = "";

    // Check length
    if (pass.length() >= 12) score += 2;
    else if (pass.length() >= 8) score += 1;
    else suggestion += "Use at least 8 characters. ";

    // Character variety
    bool up=false, low=false, dig=false, sym=false;
    for(char c : pass) {
        if(isupper(c)) up = true;
        if(islower(c)) low = true;
        if(isdigit(c)) dig = true;
        if(!isalnum(c)) sym = true;
    }
    if(up) score++;
    else suggestion += "Add uppercase letters. ";

    if(low) score++;
    else suggestion += "Add lowercase letters. ";

    if(dig) score++;
    else suggestion += "Add numbers. ";

    if(sym) score++;
    else suggestion += "Add symbols (#, @, !). ";

    // Repeated patterns
    regex repeat("(.)\\1{2,}");
    if (regex_search(pass, repeat)) {
        suggestion += "Avoid repeating characters. ";
    } else score++;

    // Weak pattern detection using Trie
    bool hasWeakPattern = false;
    for (size_t i = 0; i < pass.size(); i++) {
        for (int len = 4; len <= 8 && i + len <= pass.size(); len++) {
            string sub = pass.substr(i, len);
            transform(sub.begin(), sub.end(), sub.begin(), ::tolower);
            if (trie.search(sub)) {
                hasWeakPattern = true;
                break;
            }
        }
        if (hasWeakPattern) break;
    }
    
    if (hasWeakPattern) {
        suggestion += "Remove common weak patterns like '1234'. ";
    } else {
        score++;
    }

    string strength;
    if (score <= 3) strength = "Weak";
    else if (score <= 6) strength = "Moderate";
    else strength = "Strong";

    // Escape quotes in suggestion for JSON
    string escaped_suggestion = "";
    for (char c : suggestion) {
        if (c == '"') escaped_suggestion += "\\\"";
        else if (c == '\\') escaped_suggestion += "\\\\";
        else escaped_suggestion += c;
    }

    return {
        {"strength", strength},
        {"suggestion", escaped_suggestion}
    };
}

// ---------- HTTP API ----------
int main() {
    httplib::Server server;

    // Enable CORS and set default headers
    server.set_default_headers({
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Methods", "GET, POST, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type"}
    });

    // Handle OPTIONS requests for CORS preflight
    server.Options("/analyze", [](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        res.status = 200;

    });

    server.Post("/analyze", [](const httplib::Request& req, httplib::Response& res) {
        string password = req.get_param_value("password");

        // Input validation
        if (password.empty()) {
            string json = "{ \"strength\": \"N/A\", \"suggestion\": \"Please enter a password.\" }";
            res.set_content(json, "application/json");
            return;
        }

        auto result = analyzePassword(password);

        string json = "{ \"strength\": \"" + result["strength"] +
                      "\", \"suggestion\": \"" + result["suggestion"] + "\" }";

        res.set_content(json, "application/json");
    });

    cout << "Server running on http://localhost:5000\n";
    server.listen("0.0.0.0", 5000);
    return 0;
}