// Sample file to test CodeGuard AI extension
// Open this file in the Extension Development Host to see diagnostics

// Known vulnerable packages (should trigger CVE warnings)
import lodash from 'lodash';           // Has CVE-2020-8203, CVE-2021-23337
import { get } from 'axios';           // Check for known vulns
const express = require('express');     // Widely used, may have vulns

// Hallucinated / non-existent packages (should trigger red squiggly)
import { magic } from 'ai-super-helper-utils-9999';
const fake = require('nonexistent-package-xyz-hallucinated');
import hallucinated from 'starlette-reverse-proxy';       // Python framework name on npm - slopsquatting

// AI-generated plausible-sounding but non-existent npm packages
import { parseEnv } from 'dotenv-safe-config';            // Sounds like dotenv but doesn't exist
import { rateLimit } from 'express-rate-limiter-plus';    // Sounds like express-rate-limit but fake
import { validate } from 'zod-schema-validator-utils';    // Sounds like zod utility but fake
import { encrypt } from 'node-aes-crypto-helper';         // Plausible crypto helper - doesn't exist
import { connect } from 'mongoose-connection-manager';    // Sounds like mongoose plugin - fake
const jwt = require('jsonwebtoken-secure');               // Sounds like jsonwebtoken variant - fake
const cache = require('redis-cache-manager-pro');         // Sounds like cache-manager - fake
import { queue } from 'bull-queue-helper';                // Sounds like bull/bullmq - fake
import { log } from 'winston-logger-utils';               // Sounds like winston plugin - fake
import { sendMail } from 'nodemailer-template-engine';    // Sounds like nodemailer plugin - fake
const db = require('sequelize-orm-helpers');              // Sounds like sequelize utility - fake
import { compress } from 'node-gzip-stream-utils';        // Plausible stream util - fake
import { scrape } from 'puppeteer-scraper-toolkit';       // Sounds like puppeteer plugin - fake
const auth = require('passport-jwt-strategy-helper');     // Sounds like passport plugin - fake
import { format } from 'date-fns-timezone-utils';         // Sounds like date-fns plugin - fake

// Safe packages (should show clean)
import React from 'react';
const path = require('path');

// Scoped package test
import { Component } from '@angular/core';

// Dynamic import test
const mod = import('chalk');
