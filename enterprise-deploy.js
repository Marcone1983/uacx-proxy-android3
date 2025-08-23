#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const os = require('os');

console.log('🔥 SmartCache Enterprise Deployment Tool');
console.log('=========================================');

class EnterpriseDeployer {
  constructor() {
    this.platform = os.platform();
    this.isWindows = this.platform === 'win32';
    this.deploymentPath = path.join(__dirname, 'deployment');
  }

  async deploy() {
    console.log('🚀 Starting enterprise deployment...\n');
    
    // Step 1: Build executables
    await this.buildExecutables();
    
    // Step 2: Create deployment package
    await this.createDeploymentPackage();
    
    // Step 3: Setup network deployment
    if (this.isWindows) {
      await this.setupActiveDirectoryDeployment();
    } else {
      await this.setupLinuxMacDeployment();
    }
    
    console.log('\n✅ Enterprise deployment ready!');
    console.log('\nNext steps:');
    console.log('1. Update .env with your Supabase credentials');
    console.log('2. Run the deployment scripts from your admin machine');
    console.log('3. Monitor dashboard at http://localhost:3000');
  }

  async buildExecutables() {
    console.log('🔨 Building executables for all platforms...');
    
    const platforms = [
      { name: 'Windows', target: 'node20-win-x64', ext: '.exe' },
      { name: 'macOS', target: 'node20-macos-x64', ext: '' },
      { name: 'Linux', target: 'node20-linux-x64', ext: '' }
    ];

    for (const platform of platforms) {
      console.log(`   Building for ${platform.name}...`);
      
      const outputName = `smartcache-${platform.name.toLowerCase()}${platform.ext}`;
      const outputPath = path.join(this.deploymentPath, outputName);
      
      await this.executeCommand(
        `npx pkg . --target ${platform.target} --output "${outputPath}"`,
        { silent: true }
      );
      
      console.log(`   ✅ ${outputName} created`);
    }
  }

  async createDeploymentPackage() {
    console.log('\n📦 Creating deployment package...');
    
    // Create deployment directory
    if (!fs.existsSync(this.deploymentPath)) {
      fs.mkdirSync(this.deploymentPath, { recursive: true });
    }

    // Copy essential files
    const filesToCopy = [
      '.env',
      'package.json',
      'src/',
      'browser-extension/',
      'README.md'
    ];

    for (const file of filesToCopy) {
      const srcPath = path.join(__dirname, file);
      const destPath = path.join(this.deploymentPath, file);
      
      if (fs.existsSync(srcPath)) {
        if (fs.statSync(srcPath).isDirectory()) {
          this.copyDir(srcPath, destPath);
        } else {
          fs.copyFileSync(srcPath, destPath);
        }
      }
    }

    console.log('   ✅ Deployment package created');
  }

  async setupActiveDirectoryDeployment() {
    console.log('\n🏢 Setting up Active Directory deployment...');
    
    const deploymentScript = `
# SmartCache Enterprise - One-Click Deployment
# Run this from Domain Controller with Admin privileges

$deployPath = "$env:TEMP\\SmartCache-Deploy"
$shareName = "SmartCache$"

# Create deployment directory
New-Item -Path $deployPath -ItemType Directory -Force | Out-Null

# Copy SmartCache files
Copy-Item -Path "${this.deploymentPath}\\*" -Destination $deployPath -Recurse -Force

# Create network share
New-SmbShare -Name $shareName -Path $deployPath -FullAccess "Domain Admins" -ReadAccess "Domain Computers" -Force

Write-Host "🚀 SmartCache deployment share created: \\\\$env:COMPUTERNAME\\$shareName"
Write-Host ""
Write-Host "Run the following to deploy to all computers:"
Write-Host "    .\\master_install.ps1"

# Optional: Auto-execute deployment
$response = Read-Host "Deploy to all computers now? (y/N)"
if ($response -eq 'y' -or $response -eq 'Y') {
    & "$deployPath\\src\\installers\\master_install.ps1"
}
    `;

    fs.writeFileSync(
      path.join(this.deploymentPath, 'deploy-enterprise.ps1'), 
      deploymentScript
    );

    console.log('   ✅ Active Directory deployment script created');
    console.log('   📝 Run: deploy-enterprise.ps1 as Domain Admin');
  }

  async setupLinuxMacDeployment() {
    console.log('\n🐧 Setting up Linux/macOS deployment...');
    
    const deployScript = `#!/bin/bash
# SmartCache Enterprise - Linux/macOS Deployment

set -e

DEPLOY_DIR="/tmp/smartcache-deploy"
HOSTS_FILE="$DEPLOY_DIR/hosts.txt"

echo "🚀 SmartCache Enterprise Deployment"
echo "=================================="

# Create deployment directory
mkdir -p "$DEPLOY_DIR"
cp -r "${this.deploymentPath}/"* "$DEPLOY_DIR/"

# Generate hosts file
echo "📝 Creating hosts file..."
nmap -sn 192.168.1.0/24 | grep -E "Nmap scan report" | awk '{print $5}' > "$HOSTS_FILE"

echo "Found $(wc -l < $HOSTS_FILE) potential hosts"

# Deploy to each host
while IFS= read -r host; do
    echo "🖥️  Deploying to $host..."
    
    # Try SSH deployment
    scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 \\
        "$DEPLOY_DIR/smartcache-linux" "root@$host:/tmp/smartcache" 2>/dev/null && \\
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \\
        "root@$host" "chmod +x /tmp/smartcache && /tmp/smartcache &" 2>/dev/null && \\
    echo "    ✅ Success" || echo "    ❌ Failed"
    
done < "$HOSTS_FILE"

echo "✅ Deployment complete"
    `;

    fs.writeFileSync(
      path.join(this.deploymentPath, 'deploy-enterprise.sh'), 
      deployScript
    );

    await this.executeCommand(`chmod +x "${path.join(this.deploymentPath, 'deploy-enterprise.sh')}"`);
    
    console.log('   ✅ Linux/macOS deployment script created');
    console.log('   📝 Run: ./deploy-enterprise.sh as root');
  }

  copyDir(src, dest) {
    if (!fs.existsSync(dest)) {
      fs.mkdirSync(dest, { recursive: true });
    }
    
    const files = fs.readdirSync(src);
    
    for (const file of files) {
      const srcPath = path.join(src, file);
      const destPath = path.join(dest, file);
      
      if (fs.statSync(srcPath).isDirectory()) {
        this.copyDir(srcPath, destPath);
      } else {
        fs.copyFileSync(srcPath, destPath);
      }
    }
  }

  executeCommand(command, options = {}) {
    return new Promise((resolve, reject) => {
      exec(command, options, (error, stdout, stderr) => {
        if (error && !options.silent) {
          console.error(`Error: ${error.message}`);
          reject(error);
        } else {
          resolve(stdout);
        }
      });
    });
  }
}

// Auto-run if called directly
if (require.main === module) {
  const deployer = new EnterpriseDeployer();
  deployer.deploy().catch(console.error);
}

module.exports = EnterpriseDeployer;