/**
 * Example vulnerable JavaScript code for testing
 * This file contains intentional security vulnerabilities for demonstration
 * DO NOT USE IN PRODUCTION!
 */

const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const axios = require('axios');

const app = express();

// VULNERABILITY: Hardcoded credentials (CRITICAL)
// NOTE: These are FAKE example keys for testing - they do not work
const API_KEY = "AIzaSyEXAMPLE_FAKE_KEY_FOR_TESTING_ONLY";
const DATABASE_URL = "mongodb://admin:examplepass@localhost:27017/mydb";
const STRIPE_KEY = "sk_test_EXAMPLE_NOT_A_REAL_KEY_12345";


// VULNERABILITY: XSS (HIGH)
app.get('/profile', (req, res) => {
    const username = req.query.username;
    // Using innerHTML with user input
    res.send(`
        <script>
            document.getElementById('username').innerHTML = '${username}';
        </script>
    `);
});


// VULNERABILITY: Command Injection (CRITICAL)
app.get('/convert', (req, res) => {
    const filename = req.query.file;
    // Executing shell command with user input
    exec(`convert ${filename} output.pdf`, (error, stdout, stderr) => {
        res.send('Conversion complete');
    });
});


// VULNERABILITY: Path Traversal (HIGH)
app.get('/download', (req, res) => {
    const file = req.query.filename;
    // Reading file with user-controlled path
    fs.readFile(`./uploads/${file}`, (err, data) => {
        res.send(data);
    });
});


// VULNERABILITY: SSRF (HIGH)
app.get('/proxy', async (req, res) => {
    const url = req.query.url;
    // Making request to user-controlled URL
    const response = await axios.get(url);
    res.send(response.data);
});


// VULNERABILITY: Insecure JSON parsing (MEDIUM)
app.post('/data', (req, res) => {
    const userInput = req.body.data;
    // Parsing user input without validation
    const obj = JSON.parse(userInput);
    res.json(obj);
});


// VULNERABILITY: Using document.write (HIGH)
function displayMessage(message) {
    document.write(message);  // XSS risk
}


// VULNERABILITY: React dangerouslySetInnerHTML (HIGH)
function UserProfile({ userData }) {
    return (
        <div dangerouslySetInnerHTML={{ __html: userData.bio }} />
    );
}


// VULNERABILITY: Missing CSRF protection (MEDIUM)
app.post('/update-email', (req, res) => {
    const newEmail = req.body.email;
    // State-changing operation without CSRF token
    updateUserEmail(req.user.id, newEmail);
    res.send('Email updated');
});


// More hardcoded secrets - FAKE EXAMPLES FOR TESTING
const JWT_SECRET = "example-not-a-real-secret-for-testing";
const SENDGRID_API_KEY = "SG.EXAMPLE_FAKE_KEY.NotARealSendGridKeyForTestingOnly123456";
const TWILIO_AUTH_TOKEN = "SKEXAMPLEnotarealtokenfakefake";


// VULNERABILITY: Using HTTP instead of HTTPS (LOW)
const API_ENDPOINT = "http://api.example.com/users";


app.listen(3000, () => {
    console.log('Server running on port 3000');
});
