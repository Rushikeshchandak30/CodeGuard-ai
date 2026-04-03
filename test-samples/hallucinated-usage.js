// Demo file showing usage of hallucinated npm packages
// This file should trigger multiple slopsquatting warnings

import express from 'express';
import { magic } from 'ai-super-helper-utils-9999';
import hallucinated from 'starlette-reverse-proxy';
import { parseEnv } from 'dotenv-safe-config';
import { rateLimit } from 'express-rate-limiter-plus';
import { validate } from 'zod-schema-validator-utils';
import { encrypt } from 'node-aes-crypto-helper';
import { connect } from 'mongoose-connection-manager';
const jwt = require('jsonwebtoken-secure');
const cache = require('redis-cache-manager-pro');
import { queue } from 'bull-queue-helper';
import { log } from 'winston-logger-utils';
import { sendMail } from 'nodemailer-template-engine';
const db = require('sequelize-orm-helpers');
import { compress } from 'node-gzip-stream-utils';
import { scrape } from 'puppeteer-scraper-toolkit';
const auth = require('passport-jwt-strategy-helper');
import { format } from 'date-fns-timezone-utils';

const app = express();

// Initialize hallucinated packages with realistic usage patterns
const aiHelper = magic.initialize({apiKey: 'fake-key'});
const proxy = new hallucinated.ReverseProxy({target: 'http://localhost:3000'});
const envConfig = parseEnv(['DATABASE_URL', 'JWT_SECRET']);
const limiter = rateLimit({windowMs: 15*60*1000, max: 100});
const validator = validate({schema: {name: 'string', email: 'email'}});
const crypto = encrypt({algorithm: 'aes-256-cbc', key: 'secret-key'});
const mongoDB = connect({uri: envConfig.DATABASE_URL});
const jwtManager = jwt.create({secret: envConfig.JWT_SECRET});
const redisCache = cache.create({host: 'localhost', port: 6379});
const taskQueue = queue.create({redis: redisCache});
const logger = log.setup({level: 'info'});
const mailer = sendMail.configure({service: 'gmail', auth: {user: 'test', pass: 'test'}});
const sequelize = db.connect({dialect: 'postgres'});
const gzip = compress.create({level: 9});
const scraper = scrape.init({headless: true});
const passportAuth = auth.strategy({jwtFromRequest: 'Bearer'});
const dateFormatter = format({timezone: 'UTC'});

// Express middleware using hallucinated packages
app.use(limiter);
app.use(proxy.middleware());

// Routes demonstrating hallucinated package usage
app.post('/api/users', async (req, res) => {
    try {
        // Validate input with hallucinated validator
        const validated = validator(req.body);
        
        // Encrypt sensitive data
        const encrypted = crypto.encrypt(validated.password);
        
        // Store in database using hallucinated ORM helper
        const user = await sequelize.models.User.create({
            ...validated,
            password: encrypted
        });
        
        // Generate JWT with hallucinated JWT library
        const token = jwtManager.sign({userId: user.id});
        
        // Cache user data
        await redisCache.set(`user:${user.id}`, user, 3600);
        
        logger.info('User created', {userId: user.id});
        
        res.json({user, token});
    } catch (error) {
        logger.error('User creation failed', error);
        res.status(500).json({error: 'Internal server error'});
    }
});

app.get('/api/scrape', async (req, res) => {
    try {
        const {url} = req.query;
        
        // Use hallucinated scraper
        const result = await scraper.scrape(url);
        
        // Compress the result
        const compressed = await gzip.compress(JSON.stringify(result));
        
        res.json({data: compressed});
    } catch (error) {
        logger.error('Scraping failed', error);
        res.status(500).json({error: 'Scraping failed'});
    }
});

app.post('/api/email', async (req, res) => {
    try {
        const {to, subject, body} = req.body;
        
        // Send email using hallucinated mailer
        await mailer.send({to, subject, html: body});
        
        // Queue follow-up task
        await taskQueue.add('email-followup', {to, sentAt: new Date()});
        
        res.json({success: true});
    } catch (error) {
        logger.error('Email failed', error);
        res.status(500).json({error: 'Email failed'});
    }
});

// Background job processing with hallucinated queue
taskQueue.process('email-followup', async (job) => {
    const {to, sentAt} = job.data;
    
    // Format date with hallucinated date utility
    const formattedDate = dateFormatter.format(sentAt);
    
    logger.info(`Follow-up for ${to} sent at ${formattedDate}`);
});

// Start server
app.listen(3000, () => {
    logger.info('Server started on port 3000');
});

export default app;
// CodeGuard AI Detection Test
// Open this file in Windsurf — CodeGuard should flag these imports

// ✅ Real package — no warning
const express = require('express');

// ⚠️ Vulnerable package — CodeGuard should show CVE warning
const lodash = require('lodash'); // lodash@4.17.15 has known CVEs

// 🚨 Hallucinated/fake package — CodeGuard should flag as non-existent
const aiHelper = require('ai-super-fake-999');

// 🚨 Another hallucinated package from GHIN database
const reactTableComponent = require('react-table-component');

// ⚠️ Deprecated package — CodeGuard should suggest alternatives
const request = require('request');
