const express = require('express');
const router = express.Router();
const dnsPacket = require('dns-packet');
const fs = require('fs');
const BLOCKLIST = [
    'certs.apple.com', 'crl.apple.com', 'ocsp.apple.com', 'ocsp2.apple.com', 'valid.apple.com', 'ppq.apple.com',
    'crl3.digicert.com', 'crl4.digicert.com', 'ocsp.digicert.cn', 'ocsp.digicert.com',
    'api.revenuecat.com', 'app.revenuecat.com',
    'in.appcenter.ms', 'app-measurement.com', 'firebaselogging-pa.googleapis.com',
    'mixpanel.com', 'api.mixpanel.com'
];

router.post('/dns-query', async (req, res) => {
    try {
        const packet = dnsPacket.decode(req.body);
        if (!packet.questions || packet.questions.length === 0) {
            return res.status(400).send('Invalid DNS query');
        }

        const question = packet.questions[0];
        const requestedDomain = question.name;

        if (BLOCKLIST.includes(requestedDomain)) {
            const responsePacket = dnsPacket.encode({
                type: 'response',
                id: packet.id,
                flags: dnsPacket.AUTHORITATIVE_ANSWER,
                questions: packet.questions,
                answers: [{
                    type: 'A',
                    class: 'IN',
                    name: requestedDomain,
                    ttl: 300,
                    data: '0.0.0.0'
                }]
            });
            res.set('Content-Type', 'application/dns-message');
            return res.send(responsePacket);
        }

        const upstreamResponse = await fetch('https://cloudflare-dns.com/dns-query', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/dns-message',
                'Accept': 'application/dns-message'
            },
            body: req.body
        });

        if (!upstreamResponse.ok) {
            throw new Error(`Upstream DNS failed with status ${upstreamResponse.status}`);
        }

        const upstreamBuffer = await upstreamResponse.arrayBuffer();
        
        res.set('Content-Type', 'application/dns-message');
        res.send(Buffer.from(upstreamBuffer));

    } catch (error) {
        console.error('DNS Processing Error:', error.message);
        res.status(500).send('Internal Server Error');
    }
});

module.exports = router;
