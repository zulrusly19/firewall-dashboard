# Firewall Log Dashboard - 2-Day Assessment Project

A clean, minimalist full-stack application built to analyze firewall traffic records, differentiate permitted vs. blocked connections, and inspect detailed packet attributes.

---

## 🎯 Architecture & Features

1. **Authentication Gate**:
   - Users must **Sign In** or **Register** before accessing the dashboard. Successful registration returns to the sign-in form; the user signs in separately. Sign-in state lasts for the current browser tab and is cleared when that tab is closed.
   - User registrations are stored in SQLite locally or Neon Postgres on Vercel, with SHA-256 password hashes. This demo authentication is not production-ready.

2. **500 Synthetic Firewall Records**:
   - Sampled evenly from a 394k-line sample log.
   - **Total Records**: `500`
   - **Success (Allowed)**: `322 (64.4%)`
   - **Failed (Denied or Dropped)**: `178 (35.6%)`

3. **Interactive Records Table**:
   - Filter buttons: all, success, and failed records.
   - Live Search: Filter by IP, port, protocol, service, rule, status, severity, or attack label.
   - Pagination: 25 logs per page.
   - Click an analytics chart value to open the matching filtered records; clear the chart filter to return to the full list.

4. **Click-to-Inspect Detail Modal**:
   - Click **any row** in the table to view the full details: Source IP:Port, Destination IP:Port, Protocol, Service, Firewall Rule, Action, Packets/Bytes volume, and Raw syslog message.
   - Unsaved logs show `Not saved`. Set a case to `New`, `Investigating`, or `Resolved` and save it with analyst notes; SQLite persists changes, while static fallback mode stores them in the current browser only.
   - Both log and investigation tables support vertical and horizontal scrolling. Review saved cases and their status counts in the **Investigations** navigation view; filter the queue to show all, new, investigating, or resolved cases.
   - Open **Instructions & Approach** at the bottom of the dashboard for usage steps and a short overview of the app's stack and data flow.

5. **Node.js, SQLite & Neon Backend**:
   - Uses Node.js's built-in SQLite engine locally. When `DATABASE_URL` is configured, the server uses Neon Postgres instead.

> The dataset is synthetic. Attack labels are read from the sample records; the dashboard does not detect attacks.

---

## 🚀 How to Run the App

1. Open your terminal in this directory:
   ```powershell
   cd "C:\Users\arify\.gemini\antigravity-ide\scratch\firewall-dashboard"
   ```

2. Start the server:
   ```bash
   npm start
   ```

3. Open your browser:
   👉 **[http://localhost:3000](http://localhost:3000)**

---

## 🌐 Deploy to Vercel

Push this directory to your GitHub repository and import it into [vercel.com](https://vercel.com).
`vercel.json` is pre-configured to run `server.js`. For persistent registration and investigation data:

1. Create a Neon Postgres database from the Vercel Marketplace, or create one at [neon.tech](https://neon.tech).
2. Copy the database connection string from Neon.
3. In Vercel, open **Project Settings → Environment Variables** and add `DATABASE_URL` with that connection string for Production (and Preview if needed).
4. Redeploy the project. On its first API request, the app creates its tables and seeds the firewall records.

Do not commit the connection string to Git. Local development continues to use `database.sqlite` unless you set `DATABASE_URL` locally.
