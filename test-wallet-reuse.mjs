import "dotenv/config";
import fetch from "node-fetch";
import https from "https";
import fs from "fs";

const COORDINATOR_URL = "https://localhost:3000";

const agent = new https.Agent({
  rejectUnauthorized: false,
  ca: fs.readFileSync("./certs/cert.pem"),
});

async function testWalletReuse() {
  const testEmail = "test@example.com";

  console.log("Testing wallet reuse functionality...\n");

  // First request - should create new wallet
  console.log("1. First request (should create new wallet):");
  try {
    const response1 = await fetch(`${COORDINATOR_URL}/generate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.API_KEY,
      },
      body: JSON.stringify({
        userId: "test-user-1",
        email: testEmail
      }),
      agent: agent
    });

    const result1 = await response1.json();
    console.log("Response:", result1);
    console.log("Wallet created:", result1.address);
    console.log("Reused:", result1.reused);
    console.log();
  } catch (error) {
    console.error("Error in first request:", error.message);
  }

  // Second request - should reuse existing wallet
  console.log("2. Second request (should reuse existing wallet):");
  try {
    const response2 = await fetch(`${COORDINATOR_URL}/generate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.API_KEY,
      },
      body: JSON.stringify({
        userId: "test-user-1",
        email: testEmail
      }),
      agent: agent
    });

    const result2 = await response2.json();
    console.log("Response:", result2);
    console.log("Wallet reused:", result2.address);
    console.log("Reused:", result2.reused);
    console.log();
  } catch (error) {
    console.error("Error in second request:", error.message);
  }

  // Third request with different email - should create new wallet
  console.log("3. Third request with different email (should create new wallet):");
  try {
    const response3 = await fetch(`${COORDINATOR_URL}/generate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.API_KEY,
      },
      body: JSON.stringify({
        userId: "test-user-2",
        email: "different@example.com"
      }),
      agent: agent
    });

    const result3 = await response3.json();
    console.log("Response:", result3);
    console.log("Wallet created:", result3.address);
    console.log("Reused:", result3.reused);
    console.log();
  } catch (error) {
    console.error("Error in third request:", error.message);
  }

  console.log("Test completed!");
}

testWalletReuse().catch(console.error);