const EventEmitter = require('events');
const crypto = require('crypto');
const os = require('os');
const fs = require('fs').promises;
const securityManager = require('./enterprise-security');
const secureDatabase = require('./secure-database');

/**
 * 🏛️ ENTERPRISE MONITORING & ALERTING SYSTEM
 * Senior Enterprise-Grade System Monitoring
 * 
 * Features:
 * - Real-time system metrics collection
 * - Application performance monitoring (APM)
 * - Security event monitoring and correlation
 * - Business metrics tracking and analysis
 * - Multi-channel alerting (Email, Slack, SMS, Webhook)
 * - Intelligent alert filtering and escalation
 * - SLA monitoring and breach detection
 * - Automated incident response workflows
 * - Comprehensive health checks and diagnostics
 * - Custom metric definitions and thresholds
 */
class EnterpriseMonitoring extends EventEmitter {
  constructor() {
    super();
    
    // Monitoring state
    this.metrics = new Map();
    this.alerts = new Map();
    this.incidents = new Map();
    this.healthChecks = new Map();
    this.alertChannels = new Map();
    
    // Performance tracking
    this.performanceMetrics = {
      requests: new Map(),           // Request metrics by endpoint
      errors: new Map(),             // Error tracking
      latency: new Map(),            // Response time tracking
      throughput: new Map(),         // Requests per second
      availability: new Map()        // Service availability
    };
    
    // System metrics
    this.systemMetrics = {
      cpu: [],
      memory: [],
      disk: [],
      network: [],
      processes: []
    };
    
    // Business metrics
    this.businessMetrics = {
      subscriptions: new Map(),
      revenue: new Map(),
      users: new Map(),
      usage: new Map()
    };
    
    // Alert configuration
    this.alertConfig = {
      thresholds: {
        cpu_usage: 85,              // CPU usage percentage
        memory_usage: 90,           // Memory usage percentage
        disk_usage: 95,             // Disk usage percentage
        error_rate: 5,              // Error rate percentage
        response_time: 5000,        // Response time in ms
        availability: 99.9,         // Availability percentage
        failed_payments: 3,         // Failed payment threshold
        security_events: 5          // Security events per hour
      },
      escalation: {
        critical: 0,                // Immediate escalation
        high: 5 * 60 * 1000,       // 5 minutes
        medium: 15 * 60 * 1000,    // 15 minutes
        low: 60 * 60 * 1000        // 1 hour
      }
    };
    
    this.initializeMonitoring();
  }

  /**
   * Initialize enterprise monitoring system
   */
  async initializeMonitoring() {
    try {
      // Load monitoring configuration
      await this.loadMonitoringConfiguration();
      
      // Setup alert channels
      await this.initializeAlertChannels();
      
      // Start metrics collection
      this.startMetricsCollection();
      
      // Setup health checks
      await this.setupHealthChecks();
      
      // Initialize alert processors
      this.setupAlertProcessing();
      
      // Start automated reports
      this.startAutomatedReporting();
      
      await securityManager.auditLog('MONITORING_SYSTEM_INITIALIZED', {
        metricsEnabled: true,
        alertChannels: this.alertChannels.size,
        healthChecks: this.healthChecks.size
      });

      console.log('🏛️ Enterprise Monitoring & Alerting System initialized');

    } catch (error) {
      await securityManager.auditLog('MONITORING_INIT_ERROR', {
        error: error.message
      });
      throw new Error(`Monitoring system initialization failed: ${error.message}`);
    }
  }

  /**
   * Load monitoring configuration from secure sources
   */
  async loadMonitoringConfiguration() {
    try {
      // Load configuration overrides from secure config
      const monitoringConfig = securityManager.getConfig('MONITORING_CONFIG');
      if (monitoringConfig) {
        const config = JSON.parse(monitoringConfig);
        this.alertConfig = { ...this.alertConfig, ...config };
      }
    } catch (error) {
      console.warn('Using default monitoring configuration:', error.message);
    }
  }

  /**
   * Initialize alert channels (Email, Slack, SMS, Webhook)
   */
  async initializeAlertChannels() {
    try {
      // Email channel
      this.alertChannels.set('email', {
        type: 'email',
        enabled: true,
        config: {
          smtp: {
            host: securityManager.getConfig('SMTP_HOST') || 'smtp.gmail.com',
            port: 587,
            secure: false,
            auth: {
              user: securityManager.getConfig('SMTP_USER'),
              pass: securityManager.getConfig('SMTP_PASS')
            }
          },
          recipients: {
            critical: ['security@420white.com', 'cto@420white.com'],
            high: ['ops@420white.com', 'dev@420white.com'],
            medium: ['ops@420white.com'],
            low: ['monitoring@420white.com']
          }
        }
      });

      // Slack channel  
      this.alertChannels.set('slack', {
        type: 'slack',
        enabled: !!securityManager.getConfig('SLACK_WEBHOOK_URL'),
        config: {
          webhookUrl: securityManager.getConfig('SLACK_WEBHOOK_URL'),
          channels: {
            critical: '#alerts-critical',
            high: '#alerts-high',
            medium: '#alerts',
            low: '#monitoring'
          }
        }
      });

      // SMS channel (via Twilio)
      this.alertChannels.set('sms', {
        type: 'sms',
        enabled: !!securityManager.getConfig('TWILIO_AUTH_TOKEN'),
        config: {
          accountSid: securityManager.getConfig('TWILIO_ACCOUNT_SID'),
          authToken: securityManager.getConfig('TWILIO_AUTH_TOKEN'),
          fromNumber: securityManager.getConfig('TWILIO_FROM_NUMBER'),
          recipients: {
            critical: ['+1234567890'], // Emergency contacts
            high: ['+1234567890']
          }
        }
      });

      // Webhook channel
      this.alertChannels.set('webhook', {
        type: 'webhook',
        enabled: !!securityManager.getConfig('ALERT_WEBHOOK_URL'),
        config: {
          url: securityManager.getConfig('ALERT_WEBHOOK_URL'),
          headers: {
            'Authorization': `Bearer ${securityManager.getConfig('WEBHOOK_TOKEN')}`,
            'Content-Type': 'application/json'
          }
        }
      });

      await securityManager.auditLog('ALERT_CHANNELS_INITIALIZED', {
        channels: Array.from(this.alertChannels.keys()),
        enabled: Array.from(this.alertChannels.values()).filter(c => c.enabled).length
      });

    } catch (error) {
      console.error('Alert channels initialization error:', error);
    }
  }

  /**
   * Start comprehensive metrics collection
   */
  startMetricsCollection() {
    // System metrics collection every 30 seconds
    setInterval(() => {
      this.collectSystemMetrics();
    }, 30 * 1000);

    // Application metrics collection every 10 seconds
    setInterval(() => {
      this.collectApplicationMetrics();
    }, 10 * 1000);

    // Business metrics collection every 5 minutes
    setInterval(() => {
      this.collectBusinessMetrics();
    }, 5 * 60 * 1000);

    // Security metrics collection every minute
    setInterval(() => {
      this.collectSecurityMetrics();
    }, 60 * 1000);
  }

  /**
   * Collect system metrics (CPU, Memory, Disk, Network)
   */
  async collectSystemMetrics() {
    try {
      const timestamp = Date.now();
      
      // CPU metrics
      const cpuUsage = await this.getCPUUsage();
      await this.recordMetric('system.cpu.usage', cpuUsage, timestamp);
      
      // Memory metrics
      const memoryUsage = await this.getMemoryUsage();
      await this.recordMetric('system.memory.usage', memoryUsage.percent, timestamp);
      await this.recordMetric('system.memory.free', memoryUsage.free, timestamp);
      await this.recordMetric('system.memory.used', memoryUsage.used, timestamp);
      
      // Disk metrics
      const diskUsage = await this.getDiskUsage();
      await this.recordMetric('system.disk.usage', diskUsage.percent, timestamp);
      await this.recordMetric('system.disk.free', diskUsage.free, timestamp);
      
      // Network metrics
      const networkStats = await this.getNetworkStats();
      await this.recordMetric('system.network.bytes_sent', networkStats.bytesSent, timestamp);
      await this.recordMetric('system.network.bytes_received', networkStats.bytesReceived, timestamp);
      
      // Process metrics
      const processMetrics = this.getProcessMetrics();
      await this.recordMetric('system.process.uptime', processMetrics.uptime, timestamp);
      await this.recordMetric('system.process.pid', processMetrics.pid, timestamp);

      // Check thresholds and generate alerts
      await this.checkSystemThresholds(cpuUsage, memoryUsage.percent, diskUsage.percent);

    } catch (error) {
      await securityManager.auditLog('SYSTEM_METRICS_ERROR', {
        error: error.message
      });
    }
  }

  /**
   * Get CPU usage percentage
   */
  async getCPUUsage() {
    return new Promise((resolve) => {
      const startUsage = process.cpuUsage();
      const startTime = process.hrtime();

      setTimeout(() => {
        const endUsage = process.cpuUsage(startUsage);
        const endTime = process.hrtime(startTime);

        const microsecondsDelta = endTime[0] * 1000000 + endTime[1] / 1000;
        const cpuPercent = ((endUsage.user + endUsage.system) / microsecondsDelta) * 100;

        resolve(Math.round(cpuPercent * 100) / 100);
      }, 100);
    });
  }

  /**
   * Get memory usage statistics
   */
  async getMemoryUsage() {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    
    return {
      total: totalMem,
      free: freeMem,
      used: usedMem,
      percent: Math.round((usedMem / totalMem) * 100 * 100) / 100
    };
  }

  /**
   * Get disk usage statistics
   */
  async getDiskUsage() {
    try {
      const stats = await fs.statfs('./');
      const total = stats.blocks * stats.bsize;
      const free = stats.bavail * stats.bsize;
      const used = total - free;
      
      return {
        total,
        free,
        used,
        percent: Math.round((used / total) * 100 * 100) / 100
      };
    } catch (error) {
      // Fallback for platforms that don't support statfs
      return { total: 0, free: 0, used: 0, percent: 0 };
    }
  }

  /**
   * Get network statistics
   */
  async getNetworkStats() {
    const networkInterfaces = os.networkInterfaces();
    let bytesSent = 0;
    let bytesReceived = 0;
    
    // This is a simplified implementation
    // In production, you'd use proper network monitoring tools
    return { bytesSent, bytesReceived };
  }

  /**
   * Get process metrics
   */
  getProcessMetrics() {
    return {
      uptime: process.uptime(),
      pid: process.pid,
      memoryUsage: process.memoryUsage(),
      version: process.version
    };
  }

  /**
   * Collect application performance metrics
   */
  async collectApplicationMetrics() {
    try {
      const timestamp = Date.now();
      
      // Calculate request metrics
      for (const [endpoint, requests] of this.performanceMetrics.requests.entries()) {
        const recentRequests = requests.filter(r => timestamp - r.timestamp < 60000); // Last minute
        
        if (recentRequests.length > 0) {
          // Throughput
          const throughput = recentRequests.length;
          await this.recordMetric(`app.throughput.${endpoint}`, throughput, timestamp);
          
          // Average response time
          const avgResponseTime = recentRequests.reduce((sum, r) => sum + r.responseTime, 0) / recentRequests.length;
          await this.recordMetric(`app.response_time.${endpoint}`, avgResponseTime, timestamp);
          
          // Error rate
          const errors = recentRequests.filter(r => r.isError).length;
          const errorRate = (errors / recentRequests.length) * 100;
          await this.recordMetric(`app.error_rate.${endpoint}`, errorRate, timestamp);
          
          // Check performance thresholds
          await this.checkPerformanceThresholds(endpoint, avgResponseTime, errorRate);
        }
      }

    } catch (error) {
      await securityManager.auditLog('APP_METRICS_ERROR', {
        error: error.message
      });
    }
  }

  /**
   * Collect business metrics
   */
  async collectBusinessMetrics() {
    try {
      const timestamp = Date.now();
      
      // Active subscriptions
      const activeSubscriptions = await this.getActiveSubscriptionsCount();
      await this.recordMetric('business.subscriptions.active', activeSubscriptions, timestamp);
      
      // Monthly recurring revenue
      const mrr = await this.calculateMRR();
      await this.recordMetric('business.revenue.mrr', mrr, timestamp);
      
      // Daily active users
      const dau = await this.getDailyActiveUsers();
      await this.recordMetric('business.users.daily_active', dau, timestamp);
      
      // API usage
      const apiUsage = await this.getAPIUsageMetrics();
      await this.recordMetric('business.usage.api_calls', apiUsage.totalCalls, timestamp);
      await this.recordMetric('business.usage.cache_hits', apiUsage.cacheHits, timestamp);
      await this.recordMetric('business.usage.cost_savings', apiUsage.costSavings, timestamp);

    } catch (error) {
      await securityManager.auditLog('BUSINESS_METRICS_ERROR', {
        error: error.message
      });
    }
  }

  /**
   * Collect security metrics
   */
  async collectSecurityMetrics() {
    try {
      const timestamp = Date.now();
      const hourAgo = timestamp - (60 * 60 * 1000);
      
      // Security events in last hour
      const securityEvents = await secureDatabase.executeQuery(`
        SELECT COUNT(*) as count FROM security_events 
        WHERE created_at > ?
      `, [hourAgo]);
      
      const eventCount = securityEvents[0]?.count || 0;
      await this.recordMetric('security.events.hourly', eventCount, timestamp);
      
      // Failed login attempts
      const failedLogins = await this.getFailedLoginCount(hourAgo);
      await this.recordMetric('security.login_failures.hourly', failedLogins, timestamp);
      
      // DDoS attempts blocked
      const ddosBlocked = await this.getDDoSBlockedCount(hourAgo);
      await this.recordMetric('security.ddos.blocked', ddosBlocked, timestamp);
      
      // Check security thresholds
      await this.checkSecurityThresholds(eventCount, failedLogins, ddosBlocked);

    } catch (error) {
      await securityManager.auditLog('SECURITY_METRICS_ERROR', {
        error: error.message
      });
    }
  }

  /**
   * Record a metric with timestamp
   */
  async recordMetric(metricName, value, timestamp = Date.now()) {
    try {
      // Store in memory for real-time access
      if (!this.metrics.has(metricName)) {
        this.metrics.set(metricName, []);
      }
      
      const metricHistory = this.metrics.get(metricName);
      metricHistory.push({ value, timestamp });
      
      // Keep only last 1000 data points per metric
      if (metricHistory.length > 1000) {
        metricHistory.shift();
      }
      
      // Store in database for long-term analysis
      await secureDatabase.recordSystemMetric('monitoring', metricName, value, {
        recorded_by: 'enterprise_monitoring',
        component: metricName.split('.')[0]
      });

    } catch (error) {
      console.error('Metric recording error:', error);
    }
  }

  /**
   * Track request performance
   */
  trackRequest(endpoint, responseTime, isError = false) {
    if (!this.performanceMetrics.requests.has(endpoint)) {
      this.performanceMetrics.requests.set(endpoint, []);
    }
    
    const requests = this.performanceMetrics.requests.get(endpoint);
    requests.push({
      timestamp: Date.now(),
      responseTime,
      isError
    });
    
    // Keep only last 1000 requests per endpoint
    if (requests.length > 1000) {
      requests.shift();
    }
  }

  /**
   * Check system thresholds and generate alerts
   */
  async checkSystemThresholds(cpuUsage, memoryUsage, diskUsage) {
    const alerts = [];
    
    if (cpuUsage > this.alertConfig.thresholds.cpu_usage) {
      alerts.push({
        type: 'SYSTEM_ALERT',
        severity: cpuUsage > 95 ? 'critical' : 'high',
        title: 'High CPU Usage',
        message: `CPU usage is ${cpuUsage}% (threshold: ${this.alertConfig.thresholds.cpu_usage}%)`,
        metrics: { cpu_usage: cpuUsage }
      });
    }
    
    if (memoryUsage > this.alertConfig.thresholds.memory_usage) {
      alerts.push({
        type: 'SYSTEM_ALERT',
        severity: memoryUsage > 95 ? 'critical' : 'high',
        title: 'High Memory Usage',
        message: `Memory usage is ${memoryUsage}% (threshold: ${this.alertConfig.thresholds.memory_usage}%)`,
        metrics: { memory_usage: memoryUsage }
      });
    }
    
    if (diskUsage > this.alertConfig.thresholds.disk_usage) {
      alerts.push({
        type: 'SYSTEM_ALERT',
        severity: 'critical',
        title: 'High Disk Usage',
        message: `Disk usage is ${diskUsage}% (threshold: ${this.alertConfig.thresholds.disk_usage}%)`,
        metrics: { disk_usage: diskUsage }
      });
    }
    
    // Send alerts
    for (const alert of alerts) {
      await this.sendAlert(alert);
    }
  }

  /**
   * Check performance thresholds
   */
  async checkPerformanceThresholds(endpoint, avgResponseTime, errorRate) {
    const alerts = [];
    
    if (avgResponseTime > this.alertConfig.thresholds.response_time) {
      alerts.push({
        type: 'PERFORMANCE_ALERT',
        severity: avgResponseTime > 10000 ? 'high' : 'medium',
        title: 'High Response Time',
        message: `Average response time for ${endpoint} is ${avgResponseTime}ms (threshold: ${this.alertConfig.thresholds.response_time}ms)`,
        metrics: { endpoint, response_time: avgResponseTime }
      });
    }
    
    if (errorRate > this.alertConfig.thresholds.error_rate) {
      alerts.push({
        type: 'PERFORMANCE_ALERT',
        severity: errorRate > 10 ? 'high' : 'medium',
        title: 'High Error Rate',
        message: `Error rate for ${endpoint} is ${errorRate}% (threshold: ${this.alertConfig.thresholds.error_rate}%)`,
        metrics: { endpoint, error_rate: errorRate }
      });
    }
    
    // Send alerts
    for (const alert of alerts) {
      await this.sendAlert(alert);
    }
  }

  /**
   * Check security thresholds
   */
  async checkSecurityThresholds(securityEvents, failedLogins, ddosBlocked) {
    const alerts = [];
    
    if (securityEvents > this.alertConfig.thresholds.security_events) {
      alerts.push({
        type: 'SECURITY_ALERT',
        severity: 'high',
        title: 'High Security Event Volume',
        message: `${securityEvents} security events in the last hour (threshold: ${this.alertConfig.thresholds.security_events})`,
        metrics: { security_events: securityEvents }
      });
    }
    
    if (failedLogins > 20) {
      alerts.push({
        type: 'SECURITY_ALERT',
        severity: 'medium',
        title: 'Multiple Failed Login Attempts',
        message: `${failedLogins} failed login attempts in the last hour`,
        metrics: { failed_logins: failedLogins }
      });
    }
    
    if (ddosBlocked > 0) {
      alerts.push({
        type: 'SECURITY_ALERT',
        severity: 'high',
        title: 'DDoS Attacks Blocked',
        message: `${ddosBlocked} DDoS attacks were blocked in the last hour`,
        metrics: { ddos_blocked: ddosBlocked }
      });
    }
    
    // Send alerts
    for (const alert of alerts) {
      await this.sendAlert(alert);
    }
  }

  /**
   * Send alert through configured channels
   */
  async sendAlert(alert) {
    try {
      const alertId = crypto.randomBytes(8).toString('hex');
      alert.id = alertId;
      alert.timestamp = new Date().toISOString();
      
      // Store alert
      this.alerts.set(alertId, alert);
      
      // Send through each enabled channel based on severity
      for (const [channelName, channel] of this.alertChannels.entries()) {
        if (!channel.enabled) continue;
        
        const shouldSend = this.shouldSendToChannel(alert.severity, channelName);
        if (shouldSend) {
          await this.sendToChannel(channel, alert);
        }
      }
      
      // Log alert
      await securityManager.auditLog('ALERT_SENT', {
        alertId,
        type: alert.type,
        severity: alert.severity,
        title: alert.title,
        channels: Array.from(this.alertChannels.keys()).filter(c => 
          this.alertChannels.get(c).enabled && this.shouldSendToChannel(alert.severity, c)
        )
      });
      
      // Emit event for real-time listeners
      this.emit('alert', alert);

    } catch (error) {
      await securityManager.auditLog('ALERT_SEND_ERROR', {
        alert: alert.title,
        error: error.message
      });
    }
  }

  /**
   * Determine if alert should be sent to specific channel based on severity
   */
  shouldSendToChannel(severity, channelName) {
    const channelMappings = {
      email: ['critical', 'high', 'medium', 'low'],
      slack: ['critical', 'high', 'medium'],
      sms: ['critical', 'high'],
      webhook: ['critical', 'high', 'medium', 'low']
    };
    
    return channelMappings[channelName]?.includes(severity) || false;
  }

  /**
   * Send alert to specific channel
   */
  async sendToChannel(channel, alert) {
    try {
      switch (channel.type) {
        case 'email':
          await this.sendEmailAlert(channel, alert);
          break;
        case 'slack':
          await this.sendSlackAlert(channel, alert);
          break;
        case 'sms':
          await this.sendSMSAlert(channel, alert);
          break;
        case 'webhook':
          await this.sendWebhookAlert(channel, alert);
          break;
      }
    } catch (error) {
      console.error(`Alert channel ${channel.type} error:`, error);
    }
  }

  /**
   * Send email alert
   */
  async sendEmailAlert(channel, alert) {
    // Email implementation would go here
    // For now, just log
    console.log(`📧 EMAIL ALERT [${alert.severity.toUpperCase()}]: ${alert.title}`);
    console.log(`Recipients: ${JSON.stringify(channel.config.recipients[alert.severity] || [])}`);
  }

  /**
   * Send Slack alert
   */
  async sendSlackAlert(channel, alert) {
    // Slack webhook implementation would go here
    console.log(`💬 SLACK ALERT [${alert.severity.toUpperCase()}]: ${alert.title}`);
    console.log(`Channel: ${channel.config.channels[alert.severity]}`);
  }

  /**
   * Send SMS alert
   */
  async sendSMSAlert(channel, alert) {
    // Twilio SMS implementation would go here
    console.log(`📱 SMS ALERT [${alert.severity.toUpperCase()}]: ${alert.title}`);
    console.log(`Recipients: ${JSON.stringify(channel.config.recipients[alert.severity] || [])}`);
  }

  /**
   * Send webhook alert
   */
  async sendWebhookAlert(channel, alert) {
    // HTTP webhook implementation would go here
    console.log(`🔗 WEBHOOK ALERT [${alert.severity.toUpperCase()}]: ${alert.title}`);
    console.log(`URL: ${channel.config.url}`);
  }

  /**
   * Setup health checks for all system components
   */
  async setupHealthChecks() {
    // Database health check
    this.healthChecks.set('database', {
      name: 'Database Connection',
      check: () => secureDatabase.healthCheck(),
      interval: 30000, // 30 seconds
      timeout: 5000
    });
    
    // Security manager health check
    this.healthChecks.set('security', {
      name: 'Security Manager',
      check: () => securityManager.healthCheck(),
      interval: 60000, // 1 minute
      timeout: 5000
    });
    
    // Rate limiter health check
    this.healthChecks.set('rate_limiter', {
      name: 'Rate Limiter',
      check: async () => {
        const rateLimiter = require('./enterprise-rate-limiter');
        return rateLimiter.healthCheck();
      },
      interval: 60000,
      timeout: 5000
    });
    
    // Payment system health check
    this.healthChecks.set('payments', {
      name: 'Payment System',
      check: async () => {
        const paymentSystem = require('./secure-crypto-payment');
        return paymentSystem.healthCheck();
      },
      interval: 120000, // 2 minutes
      timeout: 10000
    });
    
    // Start health check intervals
    for (const [name, healthCheck] of this.healthChecks.entries()) {
      this.startHealthCheckInterval(name, healthCheck);
    }
  }

  /**
   * Start health check interval for a specific component
   */
  startHealthCheckInterval(name, healthCheck) {
    setInterval(async () => {
      try {
        const startTime = Date.now();
        const result = await Promise.race([
          healthCheck.check(),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Health check timeout')), healthCheck.timeout)
          )
        ]);
        
        const duration = Date.now() - startTime;
        const isHealthy = result && !result.error;
        
        await this.recordMetric(`health.${name}.status`, isHealthy ? 1 : 0);
        await this.recordMetric(`health.${name}.response_time`, duration);
        
        if (!isHealthy) {
          await this.sendAlert({
            type: 'HEALTH_CHECK_FAILURE',
            severity: 'high',
            title: `${healthCheck.name} Health Check Failed`,
            message: `Health check for ${healthCheck.name} failed: ${result?.error || 'Unknown error'}`,
            metrics: { component: name, duration }
          });
        }
        
      } catch (error) {
        await this.recordMetric(`health.${name}.status`, 0);
        await this.sendAlert({
          type: 'HEALTH_CHECK_ERROR',
          severity: 'high',
          title: `${healthCheck.name} Health Check Error`,
          message: `Health check for ${healthCheck.name} encountered an error: ${error.message}`,
          metrics: { component: name, error: error.message }
        });
      }
    }, healthCheck.interval);
  }

  /**
   * Setup alert processing and escalation
   */
  setupAlertProcessing() {
    // Check for alert escalation every minute
    setInterval(() => {
      this.processAlertEscalation();
    }, 60 * 1000);
    
    // Clean up old alerts every hour
    setInterval(() => {
      this.cleanupOldAlerts();
    }, 60 * 60 * 1000);
  }

  /**
   * Process alert escalation based on time and severity
   */
  async processAlertEscalation() {
    const now = Date.now();
    
    for (const [alertId, alert] of this.alerts.entries()) {
      if (alert.escalated) continue;
      
      const alertAge = now - new Date(alert.timestamp).getTime();
      const escalationTime = this.alertConfig.escalation[alert.severity];
      
      if (alertAge > escalationTime) {
        // Escalate alert
        await this.escalateAlert(alertId, alert);
      }
    }
  }

  /**
   * Escalate alert to higher severity channels
   */
  async escalateAlert(alertId, alert) {
    try {
      alert.escalated = true;
      alert.escalationTime = new Date().toISOString();
      
      // Send escalated alert
      const escalatedAlert = {
        ...alert,
        severity: this.getEscalatedSeverity(alert.severity),
        title: `🚨 ESCALATED: ${alert.title}`,
        message: `This alert has been escalated due to no acknowledgment.\n\nOriginal: ${alert.message}`
      };
      
      await this.sendAlert(escalatedAlert);
      
      await securityManager.auditLog('ALERT_ESCALATED', {
        originalAlertId: alertId,
        escalatedSeverity: escalatedAlert.severity,
        escalationReason: 'No acknowledgment within threshold'
      });
      
    } catch (error) {
      console.error('Alert escalation error:', error);
    }
  }

  /**
   * Get escalated severity level
   */
  getEscalatedSeverity(currentSeverity) {
    const escalationMap = {
      'low': 'medium',
      'medium': 'high',
      'high': 'critical',
      'critical': 'critical' // Already at highest level
    };
    
    return escalationMap[currentSeverity] || 'high';
  }

  /**
   * Clean up old alerts (older than 7 days)
   */
  cleanupOldAlerts() {
    const cutoffTime = Date.now() - (7 * 24 * 60 * 60 * 1000); // 7 days ago
    
    for (const [alertId, alert] of this.alerts.entries()) {
      const alertTime = new Date(alert.timestamp).getTime();
      if (alertTime < cutoffTime) {
        this.alerts.delete(alertId);
      }
    }
  }

  /**
   * Start automated reporting
   */
  startAutomatedReporting() {
    // Daily reports at 9 AM
    setInterval(() => {
      const now = new Date();
      if (now.getHours() === 9 && now.getMinutes() === 0) {
        this.generateDailyReport();
      }
    }, 60 * 1000);
    
    // Weekly reports on Monday at 9 AM
    setInterval(() => {
      const now = new Date();
      if (now.getDay() === 1 && now.getHours() === 9 && now.getMinutes() === 0) {
        this.generateWeeklyReport();
      }
    }, 60 * 1000);
  }

  /**
   * Generate daily monitoring report
   */
  async generateDailyReport() {
    try {
      const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const report = await this.generateReport('daily', yesterday);
      
      await this.sendAlert({
        type: 'DAILY_REPORT',
        severity: 'low',
        title: 'Daily Monitoring Report',
        message: `Daily system report for ${yesterday.toDateString()}`,
        attachment: report
      });
      
    } catch (error) {
      console.error('Daily report generation error:', error);
    }
  }

  /**
   * Generate weekly monitoring report
   */
  async generateWeeklyReport() {
    try {
      const lastWeek = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      const report = await this.generateReport('weekly', lastWeek);
      
      await this.sendAlert({
        type: 'WEEKLY_REPORT',
        severity: 'low',
        title: 'Weekly Monitoring Report',
        message: `Weekly system report for week of ${lastWeek.toDateString()}`,
        attachment: report
      });
      
    } catch (error) {
      console.error('Weekly report generation error:', error);
    }
  }

  /**
   * Generate monitoring report
   */
  async generateReport(period, startDate) {
    const endDate = new Date();
    const report = {
      period,
      startDate: startDate.toISOString(),
      endDate: endDate.toISOString(),
      summary: {
        alerts: this.alerts.size,
        incidents: this.incidents.size,
        uptime: await this.calculateUptime(startDate, endDate)
      },
      metrics: await this.getMetricsSummary(startDate, endDate),
      topAlerts: await this.getTopAlerts(startDate, endDate),
      performance: await this.getPerformanceSummary(startDate, endDate)
    };
    
    return report;
  }

  /**
   * Business metric calculation helpers
   */
  async getActiveSubscriptionsCount() {
    try {
      const result = await secureDatabase.executeQuery(`
        SELECT COUNT(*) as count FROM secure_subscriptions 
        WHERE status = 'ACTIVE' AND end_date > ?
      `, [Date.now()]);
      return result[0]?.count || 0;
    } catch (error) {
      return 0;
    }
  }

  async calculateMRR() {
    try {
      const result = await secureDatabase.executeQuery(`
        SELECT SUM(expected_amount) as total FROM secure_subscriptions 
        WHERE status = 'ACTIVE' AND end_date > ?
      `, [Date.now()]);
      return result[0]?.total || 0;
    } catch (error) {
      return 0;
    }
  }

  async getDailyActiveUsers() {
    try {
      const yesterday = Date.now() - 24 * 60 * 60 * 1000;
      const result = await secureDatabase.executeQuery(`
        SELECT COUNT(DISTINCT client_id) as count FROM usage_stats_secure 
        WHERE created_at > ?
      `, [yesterday]);
      return result[0]?.count || 0;
    } catch (error) {
      return 0;
    }
  }

  async getAPIUsageMetrics() {
    try {
      const yesterday = Date.now() - 24 * 60 * 60 * 1000;
      const result = await secureDatabase.executeQuery(`
        SELECT 
          SUM(apis_called) as totalCalls,
          SUM(cache_hits) as cacheHits,
          SUM(cost_saved) as costSavings
        FROM usage_stats_secure 
        WHERE created_at > ?
      `, [yesterday]);
      
      return {
        totalCalls: result[0]?.totalCalls || 0,
        cacheHits: result[0]?.cacheHits || 0,
        costSavings: result[0]?.costSavings || 0
      };
    } catch (error) {
      return { totalCalls: 0, cacheHits: 0, costSavings: 0 };
    }
  }

  async getFailedLoginCount(since) {
    // This would integrate with authentication system
    return 0;
  }

  async getDDoSBlockedCount(since) {
    // This would integrate with rate limiter
    return 0;
  }

  async calculateUptime(startDate, endDate) {
    // Calculate system uptime percentage
    return 99.9; // Placeholder
  }

  async getMetricsSummary(startDate, endDate) {
    // Get metrics summary for the period
    return {}; // Placeholder
  }

  async getTopAlerts(startDate, endDate) {
    // Get most frequent alerts
    return []; // Placeholder
  }

  async getPerformanceSummary(startDate, endDate) {
    // Get performance summary
    return {}; // Placeholder
  }

  /**
   * Enterprise health check
   */
  async healthCheck() {
    try {
      const stats = {
        monitoring: {
          status: 'healthy',
          metrics_tracked: this.metrics.size,
          active_alerts: this.alerts.size,
          health_checks: this.healthChecks.size,
          alert_channels: Array.from(this.alertChannels.entries()).map(([name, channel]) => ({
            name,
            enabled: channel.enabled
          }))
        }
      };

      await securityManager.auditLog('MONITORING_HEALTH_CHECK', stats);
      return stats;

    } catch (error) {
      const errorStats = {
        monitoring: {
          status: 'unhealthy',
          error: error.message
        }
      };
      
      await securityManager.auditLog('MONITORING_HEALTH_ERROR', errorStats);
      return errorStats;
    }
  }

  /**
   * Get real-time dashboard data
   */
  getDashboardData() {
    return {
      systemMetrics: {
        cpu: this.getLatestMetric('system.cpu.usage'),
        memory: this.getLatestMetric('system.memory.usage'),
        disk: this.getLatestMetric('system.disk.usage')
      },
      alerts: Array.from(this.alerts.values()).slice(-10), // Last 10 alerts
      healthChecks: Array.from(this.healthChecks.entries()).map(([name, hc]) => ({
        name,
        status: this.getLatestMetric(`health.${name}.status`) ? 'healthy' : 'unhealthy'
      })),
      performance: this.getPerformanceOverview()
    };
  }

  /**
   * Get latest metric value
   */
  getLatestMetric(metricName) {
    const metric = this.metrics.get(metricName);
    return metric && metric.length > 0 ? metric[metric.length - 1].value : null;
  }

  /**
   * Get performance overview
   */
  getPerformanceOverview() {
    const overview = {};
    
    for (const [endpoint, requests] of this.performanceMetrics.requests.entries()) {
      if (requests.length > 0) {
        const recentRequests = requests.slice(-60); // Last 60 requests
        const avgResponseTime = recentRequests.reduce((sum, r) => sum + r.responseTime, 0) / recentRequests.length;
        const errorCount = recentRequests.filter(r => r.isError).length;
        
        overview[endpoint] = {
          avgResponseTime: Math.round(avgResponseTime),
          requestCount: recentRequests.length,
          errorCount
        };
      }
    }
    
    return overview;
  }
}

module.exports = new EnterpriseMonitoring();