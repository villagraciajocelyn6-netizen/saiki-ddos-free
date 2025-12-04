const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

// Configuration
const PORT = 3000;
const REQUEST_LIMIT = 50;
const BANNED_IPS_FILE = path.join(__dirname, 'banned_ips.json');
const TIME_WINDOW = 60000; // 1 minute window for tracking requests

// In-memory storage for request tracking and banned IPs
let requestTracker = new Map();
let bannedIPs = new Set();

// Load banned IPs from file on startup
function loadBannedIPs() {
    try {
        if (fs.existsSync(BANNED_IPS_FILE)) {
            const data = fs.readFileSync(BANNED_IPS_FILE, 'utf8');
            const banned = JSON.parse(data);
            bannedIPs = new Set(banned.ips || []);
            console.log(`[SECURITY] Loaded ${bannedIPs.size} banned IPs from file`);
        } else {
            // Create empty file if it doesn't exist
            saveBannedIPs();
            console.log('[SECURITY] Created new banned IPs file');
        }
    } catch (error) {
        console.error('[ERROR] Failed to load banned IPs:', error);
        bannedIPs = new Set();
    }
}

// Save banned IPs to file
function saveBannedIPs() {
    try {
        const data = {
            ips: Array.from(bannedIPs),
            lastUpdated: new Date().toISOString(),
            totalBanned: bannedIPs.size
        };
        fs.writeFileSync(BANNED_IPS_FILE, JSON.stringify(data, null, 2));
        console.log(`[SECURITY] Saved ${bannedIPs.size} banned IPs to file`);
    } catch (error) {
        console.error('[ERROR] Failed to save banned IPs:', error);
    }
}

// Get real IP address (handles proxies and forwarded IPs)
function getRealIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const realIP = req.headers['x-real-ip'];
    const cfConnectingIP = req.headers['cf-connecting-ip']; // Cloudflare
    
    if (cfConnectingIP) return cfConnectingIP;
    if (realIP) return realIP;
    if (forwarded) return forwarded.split(',')[0].trim();
    return req.socket.remoteAddress || req.connection.remoteAddress;
}

// Ban an IP permanently
function banIP(ip) {
    if (!bannedIPs.has(ip)) {
        bannedIPs.add(ip);
        saveBannedIPs();
        console.log(`[BANNED] IP ${ip} has been permanently banned! Total banned: ${bannedIPs.size}`);
    }
}

// Aggressive IP blocking middleware - BLOCKS EVERYTHING IMMEDIATELY
app.use((req, res, next) => {
    const ip = getRealIP(req);
    
    // IMMEDIATE REJECTION - No processing for banned IPs
    if (bannedIPs.has(ip)) {
        console.log(`[BLOCKED] Banned IP ${ip} attempted access - CONNECTION TERMINATED`);
        // Drop connection immediately without response
        req.socket.destroy();
        return;
    }
    
    // Track requests for this IP
    const now = Date.now();
    
    if (!requestTracker.has(ip)) {
        requestTracker.set(ip, {
            count: 1,
            firstRequest: now,
            lastRequest: now
        });
    } else {
        const tracker = requestTracker.get(ip);
        
        // Reset counter if time window has passed
        if (now - tracker.firstRequest > TIME_WINDOW) {
            tracker.count = 1;
            tracker.firstRequest = now;
        } else {
            tracker.count++;
        }
        
        tracker.lastRequest = now;
        
        // Check if limit exceeded
        if (tracker.count > REQUEST_LIMIT) {
            console.log(`[WARNING] IP ${ip} exceeded limit (${tracker.count} requests) - BANNING NOW!`);
            banIP(ip);
            // Immediately destroy connection
            req.socket.destroy();
            return;
        }
        
        // Log suspicious activity (close to limit)
        if (tracker.count > REQUEST_LIMIT * 0.8) {
            console.log(`[ALERT] IP ${ip} approaching limit: ${tracker.count}/${REQUEST_LIMIT} requests`);
        }
    }
    
    next();
});

// Clean up old request tracking data every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [ip, tracker] of requestTracker.entries()) {
        // Remove tracking data older than 5 minutes if not banned
        if (now - tracker.lastRequest > 300000 && !bannedIPs.has(ip)) {
            requestTracker.delete(ip);
        }
    }
    console.log(`[CLEANUP] Active tracking: ${requestTracker.size} IPs, Banned: ${bannedIPs.size} IPs`);
}, 300000);

// Serve the HTML file
app.get('/', (req, res) => {
    const ip = getRealIP(req);
    console.log(`[ACCESS] IP ${ip} accessed the page`);
    res.sendFile(path.join(__dirname, 'index.html'));
});

// API endpoint to get request count (optional - for monitoring)
app.get('/api/status', (req, res) => {
    const ip = getRealIP(req);
    const tracker = requestTracker.get(ip);
    
    res.json({
        ip: ip,
        requests: tracker ? tracker.count : 0,
        limit: REQUEST_LIMIT,
        remaining: tracker ? Math.max(0, REQUEST_LIMIT - tracker.count) : REQUEST_LIMIT,
        banned: bannedIPs.has(ip)
    });
});

// Admin endpoint to view banned IPs (you can add authentication here)
app.get('/admin/banned', (req, res) => {
    res.json({
        totalBanned: bannedIPs.size,
        bannedIPs: Array.from(bannedIPs),
        activeTracking: requestTracker.size
    });
});

// Admin endpoint to manually unban an IP (optional)
app.get('/admin/unban/:ip', (req, res) => {
    const ipToUnban = req.params.ip;
    if (bannedIPs.has(ipToUnban)) {
        bannedIPs.delete(ipToUnban);
        saveBannedIPs();
        res.json({ success: true, message: `IP ${ipToUnban} has been unbanned` });
    } else {
        res.json({ success: false, message: `IP ${ipToUnban} is not banned` });
    }
});

// Handle 404
app.use((req, res) => {
    res.status(404).send('Not Found');
});

// Error handling
app.use((err, req, res, next) => {
    console.error('[ERROR]', err);
    res.status(500).send('Internal Server Error');
});

// Load banned IPs on startup
loadBannedIPs();

// Start server
app.listen(PORT, () => {
    console.log('='.repeat(60));
    console.log(`[SERVER] Running on http://localhost:${PORT}`);
    console.log(`[SECURITY] Request limit: ${REQUEST_LIMIT} per ${TIME_WINDOW/1000} seconds`);
    console.log(`[SECURITY] Currently banned IPs: ${bannedIPs.size}`);
    console.log(`[SECURITY] Ban list: ${BANNED_IPS_FILE}`);
    console.log('[SECURITY] Aggressive protection: ACTIVE');
    console.log('='.repeat(60));
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n[SHUTDOWN] Saving banned IPs before exit...');
    saveBannedIPs();
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n[SHUTDOWN] Saving banned IPs before exit...');
    saveBannedIPs();
    process.exit(0);
});