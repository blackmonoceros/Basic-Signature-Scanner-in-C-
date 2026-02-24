#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>

using namespace std;

// Function to safely read a binary file into a byte vector
vector<unsigned char> readFileToBuffer(const string& filePath) {
	// Open the file in binary mode and move the pointer to the end (ate - at end)
	// to quickly determine the file size.
	ifstream file(filePath, ios::binary | ios::ate);

	if (!file.is_open()) {
		cerr << "[-] Error: Cannot open file: " << filePath << endl;
		return {};
	}

	streamsize size = file.tellg();
	file.seekg(0, ios::beg); // Return to the beginning of the file

	// Avoid reading empty files
	if (size <= 0) return {};

	vector<unsigned char> buffer(size);
	if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
		return buffer;
	}

	return {}; // Return an empty vector in case of a read error
}

// Function to scan the loaded buffer for a specific signature
bool scanForSignature(const vector<unsigned char>& fileBuffer, const vector<unsigned char>& signature) {
	if (signature.empty() || fileBuffer.empty() || signature.size() > fileBuffer.size()) {
		return false;
	}

	// Use the search algorithm from the standard library to find the substring
	auto it = search(
	              fileBuffer.begin(), fileBuffer.end(),
	              signature.begin(), signature.end()
	          );

	// If the iterator doesn't point to the end of the buffer, the signature was found
	return it != fileBuffer.end();
}

int main() {
	// The file we want to scan (you need to create this in the program's directory to test it)
	string filePath = "file_to_scan.txt";

	// The virus signature. Here, we use the safe EICAR test string.
	vector<unsigned char> eicarSignature = {
		0x58, 0x35, 0x4F, 0x21, 0x50, 0x25, 0x40, 0x41, 0x50, 0x5B, 0x34, 0x5C, 0x50,
		0x5A, 0x58, 0x35, 0x34, 0x28, 0x50, 0x5E, 0x29, 0x37, 0x43, 0x43, 0x29, 0x37,
		0x7D, 0x24, 0x45, 0x49, 0x43, 0x41, 0x52, 0x2D, 0x53, 0x54, 0x41, 0x4E, 0x44,
		0x41, 0x52, 0x44, 0x2D, 0x41, 0x4E, 0x54, 0x49, 0x56, 0x49, 0x52, 0x55, 0x53,
		0x2D, 0x54, 0x45, 0x53, 0x54, 0x2D, 0x46, 0x49, 0x4C, 0x45, 0x21, 0x24, 0x48,
		0x2B, 0x48, 0x2A
	};

	cout << "[*] Starting to scan file: " << filePath << endl;

	vector<unsigned char> fileData = readFileToBuffer(filePath);

	if (fileData.empty()) {
		cout << "[-] The file is empty or there was a problem loading it." << endl;
		return 1;
	}

	// The actual scanning process
	if (scanForSignature(fileData, eicarSignature)) {
		cout << "[!] THREAT DETECTED: EICAR signature found!" << endl;
	} else {
		cout << "[+] Scan complete: The file is clean." << endl;
	}

	return 0;
}